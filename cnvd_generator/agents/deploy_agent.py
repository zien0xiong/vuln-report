#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""DeployAgent: delegate deployment to Codex CLI and validate service health."""

from __future__ import annotations

import json
import re
import socket
import subprocess
import shutil
import threading
import time
import zipfile
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

import requests

from agents.base_agent import BaseAgent
from core.config import config
from core.llm_client import LLMClient
from core.logger import PipelineLogger
from core.state import TaskState


class DeployAgentReAct(BaseAgent):
    """Codex-exec deployment agent."""

    def __init__(self, llm_client: Optional[LLMClient] = None):
        super().__init__("DeployAgent", llm_client)
        self.logger: Any = None
        self.pipeline_logger = PipelineLogger()
        deployment_cfg = config.get("deployment", {}) or {}
        self.default_port = int(deployment_cfg.get("default_port", 18100))
        self.codex_timeout = int(deployment_cfg.get("codex_exec_timeout_seconds", 7200))
        self.prefer_docker = bool(deployment_cfg.get("prefer_docker", True))
        self.docker_only = bool(deployment_cfg.get("docker_only", True))
        self.sqlmap_in_container = bool(deployment_cfg.get("sqlmap_in_container", True))
        self.docker_registry_strategy = str(
            deployment_cfg.get("docker_registry_strategy", "cn_mirror_first")
        ).strip()
        self.force_download_url = str(deployment_cfg.get("force_download_url", "")).strip()
        self.force_repository_url = str(deployment_cfg.get("force_repository_url", "")).strip()
        self.force_version = str(deployment_cfg.get("force_version", "")).strip()

    def _execute(self, state: TaskState) -> Dict[str, Any]:
        github_result = self._load_previous_output(state, "github", "github_result.json") or {}
        parsed_data = self._load_previous_output(state, "parse", "parsed.json") or {}

        forced_download_url = self.force_download_url
        if forced_download_url:
            inferred_repo = self._guess_repository_url_from_archive(forced_download_url)
            forced_repo = self.force_repository_url or inferred_repo
            github_result = dict(github_result)
            github_result["download_url"] = forced_download_url
            if forced_repo:
                github_result["repository_url"] = forced_repo
            if self.force_version:
                github_result["version"] = self.force_version
            self.pipeline_logger.info(
                f"[DeployAgent] using forced download url from config: {forced_download_url}"
            )
        elif not github_result.get("download_url"):
            raise RuntimeError("Missing GitHub download url")

        download_url = str(github_result["download_url"])
        repo_url = str(github_result.get("repository_url", ""))
        vulnerable_files = parsed_data.get("vulnerable_files", [])
        if not isinstance(vulnerable_files, list):
            vulnerable_files = []

        self.pipeline_logger.info(f"[DeployAgent] start codex delegated deploy | repo: {repo_url}")
        source_path = self._download_source(download_url, state, github_result)
        profile = self._detect_project_profile(source_path)
        self.pipeline_logger.info(f"[DeployAgent] source ready | path: {source_path}")
        self.pipeline_logger.info(f"[DeployAgent] profile | {json.dumps(profile, ensure_ascii=False)}")

        route_hint = self._extract_route_path(parsed_data.get("vulnerable_url", ""))
        deploy_result = self._deploy_via_codex_exec(source_path, profile, route_hint)

        files_to_embed = self._build_embed_list(source_path, vulnerable_files)
        output = {
            "downloaded_path": str(source_path),
            "deployed_project_path": str(deploy_result.get("project_path", source_path)),
            "project_profile": profile,
            "files_to_embed": files_to_embed,
            "deployment": deploy_result,
            "react_history": deploy_result.get("history", []),
        }

        output_path = self._get_output_path(state, "deployment.json")
        with open(output_path, "w", encoding="utf-8") as file:
            json.dump(output, file, ensure_ascii=False, indent=2)

        if deploy_result.get("status") != "running":
            raise RuntimeError(f"Deploy failed: {deploy_result.get('error', 'unknown error')}")

        return {"output_path": str(output_path), "data": output}

    # ------------------------------ codex delegate ------------------------------
    def _deploy_via_codex_exec(
        self,
        source_path: Path,
        profile: Dict[str, Any],
        route_hint: str,
    ) -> Dict[str, Any]:
        codex_path = self._detect_codex_executable()
        if not codex_path:
            return {
                "status": "failed",
                "error": "codex executable not found in PATH",
                "history": [],
                "project_path": str(source_path),
            }

        target_port = self._find_available_port()
        working_root = source_path.resolve()
        host_hint = (source_path.parent / "_host_laravel_app").resolve()
        docker_runtime = self._inspect_docker_runtime()
        log_stdout = (source_path.parent / "codex_exec_stdout.log").resolve()
        log_stderr = (source_path.parent / "codex_exec_stderr.log").resolve()
        last_msg_file = (source_path.parent / "codex_exec_last_message.txt").resolve()
        self.pipeline_logger.info(
            f"[DeployAgent] docker runtime | {json.dumps(docker_runtime, ensure_ascii=False)}"
        )
        if self.docker_only and not (
            docker_runtime.get("docker_available") and docker_runtime.get("compose_available")
        ):
            return {
                "status": "failed",
                "error": "docker_only is enabled but docker/compose is not available",
                "history": [{"event": "docker_runtime_unavailable", "runtime": docker_runtime}],
                "project_path": str(host_hint if host_hint.exists() else working_root),
            }

        prompt = self._build_codex_deploy_prompt(
            source_path=working_root,
            profile=profile,
            target_port=target_port,
            host_hint=host_hint,
            docker_runtime=docker_runtime,
            route_hint=route_hint,
        )

        cmd = [
            str(codex_path),
            "exec",
            "--skip-git-repo-check",
            "--dangerously-bypass-approvals-and-sandbox",
            "--json",
            "-C",
            str(working_root),
            "-o",
            str(last_msg_file),
            "-",
        ]

        self.pipeline_logger.info("[DeployAgent][CODEX_TASK_BEGIN] delegated deployment started")
        self.pipeline_logger.info(
            f"[DeployAgent][CODEX_CMD] {str(codex_path)} exec ... -C {working_root} -o {last_msg_file}"
        )
        start = time.time()
        timed_out = False
        return_code: Optional[int] = None
        stdout_lines: List[str] = []
        stderr_lines: List[str] = []
        early_message_text = ""
        codex_events: Dict[str, Any] = {
            "turn_completed": False,
            "last_event_time": start,
            "last_agent_message": "",
        }
        try:
            proc = subprocess.Popen(
                cmd,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                encoding="utf-8",
                errors="replace",
                cwd=str(working_root),
                bufsize=1,
            )
            assert proc.stdin is not None
            proc.stdin.write(prompt)
            proc.stdin.close()

            def _reader(pipe: Any, sink: List[str], tag: str) -> None:
                try:
                    for line in iter(pipe.readline, ""):
                        if not line:
                            break
                        sink.append(line)
                        self.pipeline_logger.info(f"[DeployAgent][{tag}] {line.rstrip()[:400]}")
                        codex_events["last_event_time"] = time.time()
                        if tag == "CODEX_STREAM_STDOUT":
                            self._collect_codex_events(line, codex_events)
                finally:
                    try:
                        pipe.close()
                    except Exception:
                        pass

            assert proc.stdout is not None and proc.stderr is not None
            t_out = threading.Thread(target=_reader, args=(proc.stdout, stdout_lines, "CODEX_STREAM_STDOUT"), daemon=True)
            t_err = threading.Thread(target=_reader, args=(proc.stderr, stderr_lines, "CODEX_STREAM_STDERR"), daemon=True)
            t_out.start()
            t_err.start()

            deadline = start + self.codex_timeout
            last_checked_message_mtime = 0.0
            while True:
                return_code = proc.poll()
                if return_code is not None:
                    break

                now = time.time()
                if now >= deadline:
                    timed_out = True
                    self.pipeline_logger.info(
                        f"[DeployAgent][CODEX_TIMEOUT] process exceeded {self.codex_timeout}s, trying graceful recover"
                    )
                    break

                # 正常结束事件已到，但进程未退出（codex 偶发卡住），主动收尾避免无限等待。
                if codex_events.get("turn_completed"):
                    idle_seconds = now - float(codex_events.get("last_event_time", now))
                    if idle_seconds >= 3:
                        self.pipeline_logger.info(
                            "[DeployAgent][CODEX_EARLY_EXIT] turn.completed observed, terminating lingering codex process"
                        )
                        break

                # 如果长时间无事件且 last_message 已可用，尝试提前恢复。
                idle_seconds = now - float(codex_events.get("last_event_time", now))
                if idle_seconds >= 20 and last_msg_file.exists():
                    mtime = last_msg_file.stat().st_mtime
                    if mtime != last_checked_message_mtime:
                        last_checked_message_mtime = mtime
                        candidate = last_msg_file.read_text(encoding="utf-8", errors="replace")
                        if candidate and self._can_recover_early(candidate, target_port, route_hint):
                            early_message_text = candidate
                            self.pipeline_logger.info(
                                "[DeployAgent][CODEX_EARLY_EXIT] valid deployment message detected, terminating lingering codex process"
                            )
                            break
                time.sleep(1)

            if proc.poll() is None:
                try:
                    proc.terminate()
                    proc.wait(timeout=8)
                except Exception:
                    try:
                        proc.kill()
                        proc.wait(timeout=8)
                    except Exception:
                        pass
                return_code = proc.poll()

            t_out.join(timeout=5)
            t_err.join(timeout=5)
            stdout_text = "".join(stdout_lines)
            stderr_text = "".join(stderr_lines)
        except Exception as error:
            return {
                "status": "failed",
                "error": f"codex exec exception: {error}",
                "history": [{"event": "codex_exception", "error": str(error)}],
                "project_path": str(working_root),
            }

        duration = time.time() - start
        log_stdout.write_text(stdout_text, encoding="utf-8", errors="replace")
        log_stderr.write_text(stderr_text, encoding="utf-8", errors="replace")

        self.pipeline_logger.info(
            f"[DeployAgent][CODEX_TASK_END] code={return_code} | duration={duration:.2f}s"
        )
        self._log_text_chunks("CODEX_STDOUT_CHUNK", stdout_text)
        self._log_text_chunks("CODEX_STDERR_CHUNK", stderr_text)

        message_text = early_message_text or str(codex_events.get("last_agent_message", "") or "")
        if last_msg_file.exists():
            file_message = last_msg_file.read_text(encoding="utf-8", errors="replace")
            if file_message.strip():
                message_text = file_message
            self._log_text_chunks("CODEX_LAST_MESSAGE", file_message)
        if not message_text:
            message_text = self._extract_last_agent_message_from_jsonl(stdout_text)
            if message_text:
                self._log_text_chunks("CODEX_LAST_MESSAGE_DERIVED", message_text)

        parsed = self._parse_codex_result(message_text, stdout_text, target_port, str(working_root), str(host_hint))
        parsed["history"] = [
            {
                "event": "codex_exec",
                "exit_code": return_code,
                "duration": duration,
                "timed_out": timed_out,
                "stdout_log": str(log_stdout),
                "stderr_log": str(log_stderr),
                "last_message_file": str(last_msg_file),
            }
        ]

        if parsed.get("status") != "running":
            inferred = self._infer_deployment_from_runtime(
                target_port=target_port,
                working_root=working_root,
                host_hint=host_hint,
                route_hint=route_hint,
            )
            if inferred:
                inferred["history"] = parsed.get("history", [])
                inferred["history"].append(
                    {
                        "event": "recovered_after_codex_hang",
                        "source": str(last_msg_file),
                        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
                    }
                )
                parsed = inferred

        parsed = self._validate_deploy_result(parsed, target_port, route_hint)
        if parsed.get("status") == "running":
            return parsed

        self.pipeline_logger.info(
            f"[DeployAgent][HEALTH_CHECK] failed | reason={parsed.get('error', 'unknown')}"
        )
        if timed_out and not parsed.get("error"):
            parsed["error"] = f"codex exec timeout ({self.codex_timeout}s)"
        elif return_code not in (None, 0) and not parsed.get("error"):
            parsed["error"] = f"codex exec exited with non-zero code {return_code}"
        return parsed

    def _build_codex_deploy_prompt(
        self,
        source_path: Path,
        profile: Dict[str, Any],
        target_port: int,
        host_hint: Path,
        docker_runtime: Dict[str, Any],
        route_hint: str,
    ) -> str:
        profile_text = json.dumps(profile, ensure_ascii=False)
        docker_text = json.dumps(docker_runtime, ensure_ascii=False)
        source_name = source_path.name
        prefer_docker_text = "true" if self.prefer_docker else "false"
        docker_only_text = "true" if self.docker_only else "false"
        route_hint_text = route_hint or "/admin/auth/roles"
        registry_strategy = self.docker_registry_strategy or "cn_mirror_first"
        return f"""
You are an autonomous deployment operator. Your job is to fully deploy and start a service for security testing.
Do not ask clarifying questions. Do not output greetings. Start execution immediately.

Project directory: {source_path}
Project profile: {profile_text}
Target port: {target_port}
If project is a PHP library, create/use a host app at: {host_hint}
Prefer Docker first: {prefer_docker_text}
Docker only mode: {docker_only_text}
Docker registry strategy: {registry_strategy}
Docker runtime probe: {docker_text}
Critical route to validate: {route_hint_text}

Hard requirements:
1) Deploy successfully and start a running HTTP service.
2) Solve environment/tooling issues by yourself. When command fails, inspect errors and collect missing information before choosing next action.
3) Prefer workspace-local temporary tools and files; avoid destructive operations.
4) Docker Compose deployment is mandatory when docker_only is true. Do not use host php/composer runtime as fallback.
5) Compose file must include services: app, db, sqlmap.
6) For PHP library host app:
   - create/update Dockerfile + docker-compose.yml + .dockerignore under host app.
   - expose target port "{target_port}:8000".
   - in host app composer.json, repositories path for source MUST use relative path "../{source_name}".
7) If image pull/build fails and strategy is cn_mirror_first, switch to available China mirrors and retry with a changed plan.
8) Start service with docker compose, verify:
   - base URL http://127.0.0.1:{target_port} is reachable
   - route "{route_hint_text}" is reachable and NOT 404
9) Keep compact step logs (start/end/duration/failure reason) for:
   create-project, config-repo, require-package, key-generate/init, service-start, health-check.
10) Do not wait forever for foreground processes. When service is up, output final JSON and exit.
11) At the end, print ONLY one JSON object in your final message with fields:
{{
  "status": "running" or "failed",
  "base_url": "http://127.0.0.1:PORT",
  "port": PORT_NUMBER,
  "project_path": "absolute path used to run service",
  "start_command": "command used to start service",
  "compose_services": ["app","db","sqlmap", "..."],
  "notes": "brief summary"
}}
12) If failed, set status=failed and provide actionable notes.
"""

    def _inspect_docker_runtime(self) -> Dict[str, Any]:
        info: Dict[str, Any] = {
            "prefer_docker": self.prefer_docker,
            "docker_available": False,
            "compose_available": False,
            "docker_version": "",
            "compose_version": "",
            "error": "",
        }
        if not self.prefer_docker:
            return info

        try:
            docker_ver = subprocess.run(
                ["docker", "--version"],
                capture_output=True,
                text=True,
                timeout=10,
                encoding="utf-8",
                errors="replace",
            )
            if docker_ver.returncode == 0:
                info["docker_available"] = True
                info["docker_version"] = (docker_ver.stdout or docker_ver.stderr or "").strip()
        except Exception as error:
            info["error"] = f"docker --version failed: {error}"

        try:
            compose_ver = subprocess.run(
                ["docker", "compose", "version"],
                capture_output=True,
                text=True,
                timeout=10,
                encoding="utf-8",
                errors="replace",
            )
            if compose_ver.returncode == 0:
                info["compose_available"] = True
                info["compose_version"] = (compose_ver.stdout or compose_ver.stderr or "").strip()
            elif not info["error"]:
                info["error"] = (compose_ver.stderr or compose_ver.stdout or "").strip()[:300]
        except Exception as error:
            if not info["error"]:
                info["error"] = f"docker compose version failed: {error}"
        return info

    def _parse_codex_result(
        self,
        last_message: str,
        stdout_text: str,
        default_port: int,
        default_project_path: str,
        host_hint: str,
    ) -> Dict[str, Any]:
        blob = self._extract_json_blob(last_message) or self._extract_json_blob(stdout_text)
        if isinstance(blob, dict):
            status = str(blob.get("status", "")).strip().lower()
            base_url = str(blob.get("base_url", "")).strip()
            port_value = blob.get("port", default_port)
            try:
                port = int(port_value)
            except Exception:
                port = default_port
            if base_url:
                parsed_url = urlparse(base_url if "://" in base_url else f"http://{base_url}")
                if parsed_url.port:
                    port = int(parsed_url.port)
            base_url = self._normalize_base_url(base_url, port)
            project_path = str(blob.get("project_path", "")).strip() or default_project_path
            if status not in {"running", "failed"}:
                status = "running" if base_url else "failed"
            compose_services_raw = blob.get("compose_services", [])
            compose_services = compose_services_raw if isinstance(compose_services_raw, list) else []
            return {
                "status": status,
                "base_url": base_url,
                "port": port,
                "project_path": project_path,
                "start_command": str(blob.get("start_command", "")).strip(),
                "notes": str(blob.get("notes", "")).strip(),
                "compose_services": [str(item) for item in compose_services if str(item).strip()],
                "error": str(blob.get("error", "")).strip() if status == "failed" else "",
            }

        url_match = re.search(r"http://127\.0\.0\.1:(\d+)", f"{last_message}\n{stdout_text}")
        if url_match:
            port = int(url_match.group(1))
            return {
                "status": "running",
                "base_url": self._normalize_base_url(f"http://127.0.0.1:{port}", port),
                "port": port,
                "project_path": host_hint if Path(host_hint).exists() else default_project_path,
                "start_command": "",
                "notes": "derived from codex output url",
                "compose_services": [],
                "error": "",
            }

        return {
            "status": "failed",
            "base_url": self._normalize_base_url("", default_port),
            "port": default_port,
            "project_path": default_project_path,
            "start_command": "",
            "notes": "",
            "compose_services": [],
            "error": "cannot parse codex final result JSON",
        }

    def _validate_deploy_result(
        self,
        parsed: Dict[str, Any],
        target_port: int,
        route_hint: str,
    ) -> Dict[str, Any]:
        if parsed.get("status") != "running":
            return parsed

        port_value = parsed.get("port", target_port)
        try:
            port = int(port_value)
        except Exception:
            port = target_port
        parsed["port"] = port
        parsed["base_url"] = self._normalize_base_url(str(parsed.get("base_url", "")), port)

        if self.docker_only:
            compose_dir = Path(str(parsed.get("project_path", "")).strip() or ".")
            if not compose_dir.is_absolute():
                compose_dir = compose_dir.resolve()
            compose_info = self._inspect_compose_services(compose_dir)
            parsed["compose_services"] = compose_info.get("services", [])
            parsed["compose_project"] = compose_info.get("project_path", str(compose_dir))
            if not compose_info.get("ok"):
                parsed["status"] = "failed"
                parsed["error"] = compose_info.get("error", "docker compose service inspection failed")
                return parsed

            start_command = str(parsed.get("start_command", "")).strip()
            if not self._is_docker_start_command(start_command):
                host_runtime_markers = ("php -s", "artisan serve", "php artisan", "composer ")
                lower_cmd = start_command.lower()
                if any(marker in lower_cmd for marker in host_runtime_markers):
                    parsed["status"] = "failed"
                    parsed["error"] = "docker_only is enabled, but codex returned host-runtime start_command"
                    return parsed
                parsed["start_command"] = "docker compose up -d --build (validated)"

            services_lower = {str(item).strip().lower() for item in compose_info.get("services", [])}
            required = {"app", "db", "sqlmap"}
            missing = sorted(list(required - services_lower))
            if missing:
                parsed["status"] = "failed"
                parsed["error"] = f"docker compose missing required services: {', '.join(missing)}"
                return parsed

        if not self._is_port_open(port):
            parsed["status"] = "failed"
            parsed["error"] = f"service not reachable on port {port} after codex execution"
            return parsed

        route_probe = self._probe_http_route(parsed["base_url"], route_hint)
        parsed["route_probe"] = route_probe
        if not route_probe.get("reachable"):
            parsed["status"] = "failed"
            parsed["error"] = f"route probe failed: {route_probe.get('error', 'unknown')}"
            return parsed
        if int(route_probe.get("status_code") or 0) == 404:
            parsed["status"] = "failed"
            parsed["error"] = f"route probe returned 404: {route_probe.get('url', '')}"
            return parsed

        self.pipeline_logger.info(
            f"[DeployAgent][HEALTH_CHECK] success | base_url={parsed.get('base_url')} | route={route_probe.get('url')} | code={route_probe.get('status_code')}"
        )
        return parsed

    def _infer_deployment_from_runtime(
        self,
        target_port: int,
        working_root: Path,
        host_hint: Path,
        route_hint: str,
    ) -> Optional[Dict[str, Any]]:
        if not self._is_port_open(target_port):
            return None

        base_url = self._normalize_base_url("", target_port)
        route_probe = self._probe_http_route(base_url, route_hint)
        if not route_probe.get("reachable") or int(route_probe.get("status_code") or 0) == 404:
            return None

        if self.docker_only:
            candidates = [host_hint, working_root]
            compose_pick = self._find_compose_project_with_required_services(candidates)
            if not compose_pick:
                return None
            return {
                "status": "running",
                "base_url": base_url,
                "port": target_port,
                "project_path": compose_pick["project_path"],
                "start_command": "docker compose up -d --build (inferred)",
                "compose_services": compose_pick["services"],
                "route_probe": route_probe,
                "notes": "inferred from running docker compose services and healthy route",
                "error": "",
            }

        return {
            "status": "running",
            "base_url": base_url,
            "port": target_port,
            "project_path": str(working_root),
            "start_command": "",
            "compose_services": [],
            "route_probe": route_probe,
            "notes": "inferred from open port and healthy route",
            "error": "",
        }

    def _find_compose_project_with_required_services(self, candidates: List[Path]) -> Optional[Dict[str, Any]]:
        required = {"app", "db", "sqlmap"}
        for candidate in candidates:
            info = self._inspect_compose_services(candidate)
            if not info.get("ok"):
                continue
            services = [str(item) for item in info.get("services", [])]
            service_lower = {item.lower() for item in services}
            if required.issubset(service_lower):
                return {"project_path": str(candidate), "services": services}
        return None

    def _inspect_compose_services(self, project_path: Path) -> Dict[str, Any]:
        info: Dict[str, Any] = {
            "ok": False,
            "services": [],
            "error": "",
            "project_path": str(project_path),
        }
        if not project_path or not project_path.exists():
            info["error"] = f"project path not found: {project_path}"
            return info

        compose_candidates = (
            project_path / "docker-compose.yml",
            project_path / "docker-compose.yaml",
            project_path / "compose.yml",
            project_path / "compose.yaml",
        )
        if not any(path.exists() for path in compose_candidates):
            info["error"] = f"compose file not found in {project_path}"
            return info

        try:
            result = subprocess.run(
                ["docker", "compose", "config", "--services"],
                capture_output=True,
                text=True,
                timeout=20,
                cwd=str(project_path),
                encoding="utf-8",
                errors="replace",
            )
            if result.returncode != 0:
                info["error"] = (result.stderr or result.stdout or "").strip()[:400]
                return info
            services = [line.strip() for line in (result.stdout or "").splitlines() if line.strip()]
            info["services"] = services
            info["ok"] = True
            return info
        except Exception as error:
            info["error"] = str(error)
            return info

    def _is_docker_start_command(self, start_command: str) -> bool:
        command = str(start_command or "").strip().lower()
        if not command:
            return False
        return "docker compose" in command or "docker-compose" in command

    def _probe_http_route(self, base_url: str, route_hint: str) -> Dict[str, Any]:
        route_path = self._normalize_route_path(route_hint)
        normalized_base = self._normalize_base_url(base_url, self.default_port)
        url = f"{normalized_base.rstrip('/')}{route_path}"
        try:
            response = requests.get(url, timeout=12, allow_redirects=False)
            return {
                "reachable": True,
                "status_code": int(response.status_code),
                "url": url,
                "error": "",
            }
        except Exception as error:
            return {
                "reachable": False,
                "status_code": None,
                "url": url,
                "error": str(error),
            }

    def _extract_route_path(self, vulnerable_url: Any) -> str:
        raw = str(vulnerable_url or "").strip()
        if not raw:
            return "/admin/auth/roles"
        try:
            parsed = urlparse(raw if "://" in raw else f"http://127.0.0.1{raw}")
            path = parsed.path or "/"
            if parsed.query:
                path = f"{path}?{parsed.query}"
            return self._normalize_route_path(path)
        except Exception:
            return "/admin/auth/roles"

    def _normalize_route_path(self, path: str) -> str:
        text = str(path or "").strip()
        if not text:
            return "/admin/auth/roles"
        if text.startswith("http://") or text.startswith("https://"):
            try:
                parsed = urlparse(text)
                text = parsed.path or "/"
                if parsed.query:
                    text = f"{text}?{parsed.query}"
            except Exception:
                text = "/admin/auth/roles"
        if not text.startswith("/"):
            text = f"/{text}"
        return text

    def _normalize_base_url(self, base_url: str, fallback_port: int) -> str:
        raw = str(base_url or "").strip()
        if not raw:
            return f"http://127.0.0.1:{fallback_port}"
        raw = raw if "://" in raw else f"http://{raw}"
        try:
            parsed = urlparse(raw)
            scheme = parsed.scheme or "http"
            host = parsed.hostname or "127.0.0.1"
            port = parsed.port or fallback_port
            return f"{scheme}://{host}:{port}"
        except Exception:
            return f"http://127.0.0.1:{fallback_port}"

    def _collect_codex_events(self, line: str, tracker: Dict[str, Any]) -> None:
        raw = str(line or "").strip()
        if not raw.startswith("{"):
            return
        try:
            event = json.loads(raw)
        except Exception:
            return
        event_type = str(event.get("type", "")).strip()
        if event_type == "turn.completed":
            tracker["turn_completed"] = True
            return
        if event_type != "item.completed":
            return
        item = event.get("item", {}) if isinstance(event.get("item"), dict) else {}
        if item.get("type") == "agent_message":
            text = str(item.get("text", "")).strip()
            if text:
                tracker["last_agent_message"] = text

    def _can_recover_early(self, message_text: str, target_port: int, route_hint: str) -> bool:
        try:
            parsed = self._parse_codex_result(
                last_message=message_text,
                stdout_text="",
                default_port=target_port,
                default_project_path="",
                host_hint="",
            )
            parsed = self._validate_deploy_result(parsed, target_port, route_hint)
            return parsed.get("status") == "running"
        except Exception:
            return False

    # ------------------------------ logging helpers ------------------------------
    def _log_text_chunks(self, tag: str, text: str, max_lines: int = 120) -> None:
        lines = [line for line in (text or "").splitlines() if line.strip()]
        if not lines:
            return
        for line in lines[:max_lines]:
            self.pipeline_logger.info(f"[DeployAgent][{tag}] {line[:400]}")
        if len(lines) > max_lines:
            self.pipeline_logger.info(f"[DeployAgent][{tag}] ... truncated {len(lines) - max_lines} lines ...")

    def _extract_json_blob(self, text: str) -> Optional[Dict[str, Any]]:
        if not text:
            return None
        text = str(text).strip()
        try:
            parsed = json.loads(text)
            if isinstance(parsed, dict):
                return parsed
        except Exception:
            pass

        for raw_line in reversed(text.splitlines()):
            line = raw_line.strip()
            if not (line.startswith("{") and line.endswith("}")):
                continue
            try:
                parsed = json.loads(line)
                if isinstance(parsed, dict):
                    return parsed
            except Exception:
                continue

        start = text.find("{")
        end = text.rfind("}")
        if start >= 0 and end > start:
            fragment = text[start : end + 1]
            try:
                parsed = json.loads(fragment)
                if isinstance(parsed, dict):
                    return parsed
            except Exception:
                return None
        return None

    def _extract_last_agent_message_from_jsonl(self, stdout_text: str) -> str:
        last_text = ""
        for raw_line in (stdout_text or "").splitlines():
            line = raw_line.strip()
            if not line.startswith("{"):
                continue
            try:
                event = json.loads(line)
            except Exception:
                continue
            if event.get("type") != "item.completed":
                continue
            item = event.get("item", {}) if isinstance(event.get("item"), dict) else {}
            if item.get("type") == "agent_message":
                text = str(item.get("text", "")).strip()
                if text:
                    last_text = text
        return last_text

    def _guess_repository_url_from_archive(self, download_url: str) -> str:
        raw = str(download_url or "").strip()
        if not raw:
            return ""
        try:
            parsed = urlparse(raw)
            parts = [part for part in parsed.path.split("/") if part]
            # /owner/repo/archive/refs/tags/v1.2.3.zip
            # /owner/repo/archive/refs/heads/main.zip
            if len(parts) >= 3 and parts[2] == "archive":
                owner = parts[0]
                repo = parts[1]
                if owner and repo:
                    return f"{parsed.scheme}://{parsed.netloc}/{owner}/{repo}"
        except Exception:
            return ""
        return ""

    def _detect_codex_executable(self) -> Optional[Path]:
        try:
            result = subprocess.run(
                "where codex",
                shell=True,
                capture_output=True,
                text=True,
                timeout=10,
                encoding="utf-8",
                errors="replace",
            )
            if result.returncode == 0:
                candidates: List[Path] = []
                for line in (result.stdout or "").splitlines():
                    path = Path(line.strip())
                    if path.exists():
                        candidates.append(path)
                for path in candidates:
                    if path.suffix.lower() in {".exe", ".cmd", ".bat"}:
                        return path
                if candidates:
                    return candidates[0]
        except Exception:
            pass
        try:
            for name in ("codex.cmd", "codex.exe", "codex.bat", "codex"):
                found = shutil.which(name)
                if found:
                    return Path(found)
        except Exception:
            pass
        return None

    # ------------------------------ source + profile ------------------------------
    def _read_json_file(self, path: Path) -> Dict[str, Any]:
        try:
            with open(path, "r", encoding="utf-8") as file:
                data = json.load(file)
            return data if isinstance(data, dict) else {}
        except Exception:
            return {}

    def _detect_project_profile(self, source_path: Path) -> Dict[str, Any]:
        composer_path = source_path / "composer.json"
        package_json_path = source_path / "package.json"
        requirements_path = source_path / "requirements.txt"

        if composer_path.exists():
            composer_data = self._read_json_file(composer_path)
            project_type = str(composer_data.get("type", "")).lower()
            package_name = str(composer_data.get("name", "")).strip()
            has_artisan = (source_path / "artisan").exists()
            has_public_index = (source_path / "public" / "index.php").exists()
            is_runnable = has_artisan and has_public_index
            return {
                "ecosystem": "php",
                "is_library": project_type == "library",
                "is_runnable": is_runnable,
                "package_name": package_name,
                "composer_type": project_type,
                "reason": "php project detected from composer.json",
            }

        if requirements_path.exists():
            return {
                "ecosystem": "python",
                "is_library": False,
                "is_runnable": (source_path / "manage.py").exists() or (source_path / "app.py").exists(),
                "reason": "python project detected from requirements.txt",
            }

        if package_json_path.exists():
            pkg = self._read_json_file(package_json_path)
            scripts = pkg.get("scripts", {}) if isinstance(pkg.get("scripts"), dict) else {}
            return {
                "ecosystem": "node",
                "is_library": False,
                "is_runnable": "start" in scripts,
                "reason": "node project detected from package.json",
            }

        return {"ecosystem": "unknown", "is_library": False, "is_runnable": False, "reason": "unknown project type"}

    def _download_source(self, download_url: str, state: TaskState, github_result: Dict[str, Any]) -> Path:
        task_dir = self.state_manager.get_task_dir(state.report_name)
        source_dir = task_dir / "03_sourcecode"
        source_dir.mkdir(parents=True, exist_ok=True)

        existing_dirs = [item for item in source_dir.iterdir() if item.is_dir() and not item.name.startswith("_")]
        if existing_dirs:
            self.pipeline_logger.info(f"[DeployAgent] use existing source: {existing_dirs[0]}")
            return existing_dirs[0]

        candidate_urls = self._build_download_candidates(download_url, github_result)
        zip_path = source_dir / "source.zip"
        last_error = ""
        downloaded = False
        for idx, candidate_url in enumerate(candidate_urls, 1):
            self.pipeline_logger.info(
                f"[DeployAgent] download source try {idx}/{len(candidate_urls)}: {candidate_url}"
            )
            try:
                response = requests.get(candidate_url, timeout=120, stream=True)
                response.raise_for_status()
                with open(zip_path, "wb") as file:
                    for chunk in response.iter_content(chunk_size=8192):
                        if chunk:
                            file.write(chunk)
                downloaded = True
                break
            except Exception as error:
                last_error = str(error)
                self.pipeline_logger.info(f"[DeployAgent] download failed: {candidate_url} | error: {last_error}")
                zip_path.unlink(missing_ok=True)

        if not downloaded:
            self.pipeline_logger.info(
                f"[DeployAgent] zip download all failed, fallback to git clone | reason: {last_error}"
            )
            cloned = self._download_via_git_clone(source_dir, github_result, download_url)
            if cloned:
                return cloned
            raise RuntimeError(f"source download failed after {len(candidate_urls)} attempts: {last_error}")

        with zipfile.ZipFile(zip_path, "r") as zip_file:
            zip_file.extractall(source_dir)
        zip_path.unlink(missing_ok=True)

        extracted_dirs = [item for item in source_dir.iterdir() if item.is_dir() and not item.name.startswith("_")]
        return extracted_dirs[0] if extracted_dirs else source_dir

    def _download_via_git_clone(
        self,
        source_dir: Path,
        github_result: Dict[str, Any],
        download_url: str,
    ) -> Optional[Path]:
        git_exe = shutil.which("git")
        repo_url = str(github_result.get("repository_url", "")).strip()
        if not git_exe or not repo_url:
            self.pipeline_logger.info(
                f"[DeployAgent] git clone fallback unavailable | git={bool(git_exe)} repo_url={bool(repo_url)}"
            )
            return None

        repo_info = github_result.get("repository_info", {}) if isinstance(github_result.get("repository_info"), dict) else {}
        default_branch = str(repo_info.get("default_branch", "main")).strip() or "main"
        branch_candidates = self._build_branch_candidates(default_branch, download_url)

        for branch in branch_candidates:
            target_dir = source_dir / f"repo_{branch.replace('/', '_')}"
            if target_dir.exists():
                shutil.rmtree(target_dir, ignore_errors=True)
            cmd = [git_exe, "clone", "--depth", "1", "--branch", branch, repo_url, str(target_dir)]
            self.pipeline_logger.info(f"[DeployAgent] git clone try branch={branch}")
            try:
                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=300,
                    encoding="utf-8",
                    errors="replace",
                )
                if result.returncode == 0 and target_dir.exists():
                    self.pipeline_logger.info(f"[DeployAgent] git clone success | branch={branch}")
                    return target_dir
                self.pipeline_logger.info(
                    f"[DeployAgent] git clone failed | branch={branch} | code={result.returncode} | stderr={(result.stderr or '').strip()[:300]}"
                )
            except Exception as error:
                self.pipeline_logger.info(f"[DeployAgent] git clone exception | branch={branch} | error={error}")

        # final fallback: no branch specified
        target_dir = source_dir / "repo_default"
        if target_dir.exists():
            shutil.rmtree(target_dir, ignore_errors=True)
        cmd = [git_exe, "clone", "--depth", "1", repo_url, str(target_dir)]
        self.pipeline_logger.info("[DeployAgent] git clone try default branch")
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300,
                encoding="utf-8",
                errors="replace",
            )
            if result.returncode == 0 and target_dir.exists():
                self.pipeline_logger.info("[DeployAgent] git clone success | default branch")
                return target_dir
            self.pipeline_logger.info(
                f"[DeployAgent] git clone failed | default branch | code={result.returncode} | stderr={(result.stderr or '').strip()[:300]}"
            )
        except Exception as error:
            self.pipeline_logger.info(f"[DeployAgent] git clone exception | default branch | error={error}")
        return None

    def _build_branch_candidates(self, default_branch: str, download_url: str) -> List[str]:
        candidates: List[str] = []
        raw_url = str(download_url or "")
        match = re.search(r"/refs/heads/([^/.]+(?:\.[^/.]+)*)\.zip$", raw_url)
        if match:
            candidates.append(match.group(1))
        candidates.append(default_branch)
        if default_branch.lower() != "main":
            candidates.append("main")
        if default_branch.lower() != "master":
            candidates.append("master")
        deduped: List[str] = []
        seen = set()
        for item in candidates:
            key = item.strip()
            if key and key not in seen:
                deduped.append(key)
                seen.add(key)
        return deduped

    def _sanitize_download_url(self, download_url: str, github_result: Dict[str, Any]) -> str:
        # Backward-compat helper: keep existing API but return the first candidate.
        return self._build_download_candidates(download_url, github_result)[0]

    def _build_download_candidates(self, download_url: str, github_result: Dict[str, Any]) -> List[str]:
        candidates: List[str] = []
        raw_url = str(download_url or "").strip()
        repo_url = str(github_result.get("repository_url", "")).rstrip("/")
        repo_info = github_result.get("repository_info", {}) if isinstance(github_result.get("repository_info"), dict) else {}
        default_branch = str(repo_info.get("default_branch", "main")).strip() or "main"
        explicit_candidates = github_result.get("download_candidates", [])

        if isinstance(explicit_candidates, list):
            for item in explicit_candidates:
                value = str(item or "").strip()
                if value and not re.search(r"[\u4e00-\u9fff]", value):
                    candidates.append(value)

        if raw_url and not re.search(r"[\u4e00-\u9fff]", raw_url):
            candidates.append(raw_url)

        if repo_url:
            candidates.append(f"{repo_url}/archive/refs/heads/{default_branch}.zip")
            # Common fallback branches in case metadata/default branch is wrong.
            if default_branch.lower() != "main":
                candidates.append(f"{repo_url}/archive/refs/heads/main.zip")
            if default_branch.lower() != "master":
                candidates.append(f"{repo_url}/archive/refs/heads/master.zip")

        deduped: List[str] = []
        seen = set()
        for url in candidates:
            if url and url not in seen:
                deduped.append(url)
                seen.add(url)
        return deduped

    def _build_embed_list(self, source_path: Path, vulnerable_files: List[str]) -> List[Dict[str, str]]:
        files_to_embed: List[Dict[str, str]] = []
        for file_path in vulnerable_files:
            clean_path = str(file_path).lstrip("./").lstrip("\\/")
            full_path = source_path / clean_path
            if full_path.exists():
                files_to_embed.append(
                    {
                        "original_path": str(file_path),
                        "source_path": str(full_path),
                        "display_name": full_path.name,
                    }
                )
        return files_to_embed

    # ------------------------------ networking helpers ------------------------------
    def _is_port_open(self, port: int) -> bool:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            result = sock.connect_ex(("127.0.0.1", port))
            sock.close()
            return result == 0
        except Exception:
            return False

    def _find_available_port(self) -> int:
        for port in range(self.default_port, self.default_port + 100):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                result = sock.connect_ex(("127.0.0.1", port))
                sock.close()
                if result != 0:
                    return port
            except Exception:
                continue
        return self.default_port
