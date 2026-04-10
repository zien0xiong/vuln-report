#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""SqlmapAgent - execute sqlmap and render final output screenshot."""

from __future__ import annotations

import json
import shlex
import subprocess
import textwrap
import time
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

import requests

from agents.base_agent import BaseAgent
from core.config import config
from core.state import TaskState


class SqlmapAgent(BaseAgent):
    """SQLMap执行Agent"""

    def __init__(self, llm_client=None):
        super().__init__("SqlmapAgent", llm_client)
        deploy_cfg = config.get("deployment", {}) or {}
        self.sqlmap_in_container = bool(deploy_cfg.get("sqlmap_in_container", True))
        self.sqlmap_timeout = int(deploy_cfg.get("sqlmap_timeout_seconds", 600))

    def _execute(self, state: TaskState) -> Dict[str, Any]:
        parsed_data = self._load_previous_output(state, "parse", "parsed.json")
        deployment_data = self._load_previous_output(state, "deploy", "deployment.json")

        if not parsed_data:
            raise RuntimeError("找不到ParseAgent的输出")

        sqlmap_cmd = str(parsed_data.get("sqlmap_command", "")).strip()
        if not sqlmap_cmd:
            self.logger.warning("没有sqlmap命令，跳过此步骤")
            return {"output_path": None, "data": {"executed": False, "reason": "No sqlmap command"}}

        deployment = deployment_data.get("deployment", {}) if isinstance(deployment_data, dict) else {}
        base_url = str(deployment.get("base_url", "")).strip()
        project_path = Path(str(deployment.get("project_path", "")).strip() or ".")
        route_path = self._extract_route_path(parsed_data.get("vulnerable_url", "")) or "/admin/auth/roles"

        task_dir = Path(f"workspace/{state.report_name}")
        task_dir.mkdir(parents=True, exist_ok=True)
        test_txt = task_dir / "test.txt"
        if not test_txt.exists():
            self._create_test_txt_from_command(sqlmap_cmd, base_url, route_path, test_txt)

        sqlmap_dir = task_dir / "05_sqlmap"
        sqlmap_dir.mkdir(parents=True, exist_ok=True)
        screenshot_path = sqlmap_dir / "sqlmap_result.png"
        log_path = sqlmap_dir / "sqlmap_output.txt"

        route_probe = self._probe_route(base_url, route_path)
        if not route_probe.get("reachable"):
            result = {
                "executed": False,
                "error": f"目标路由不可达: {route_probe.get('error', 'unknown')}",
                "failure_reason": "route_unreachable",
                "route_probe": route_probe,
                "screenshot_path": None,
                "output_log": None,
                "vulnerability_confirmed": False,
                "return_code": None,
                "timed_out": False,
            }
            self._write_result(state, result)
            return {"output_path": str(self._get_output_path(state, "sqlmap_result.json")), "data": result}

        if int(route_probe.get("status_code") or 0) == 404:
            report_text = (
                "=== SQLMAP EXECUTION REPORT ===\n"
                f"failure_reason: route_404\n"
                f"url: {route_probe.get('url')}\n"
                "detail: deploy step did not expose expected route for vulnerability reproduction.\n"
            )
            log_path.write_text(report_text, encoding="utf-8", errors="replace")
            self._render_text_screenshot(report_text, screenshot_path)
            result = {
                "executed": False,
                "error": "目标路由返回404，跳过sqlmap执行",
                "failure_reason": "route_404",
                "route_probe": route_probe,
                "screenshot_path": str(screenshot_path),
                "output_log": str(log_path),
                "vulnerability_confirmed": False,
                "return_code": None,
                "timed_out": False,
            }
            self._write_result(state, result)
            return {"output_path": str(self._get_output_path(state, "sqlmap_result.json")), "data": result}

        try:
            if self.sqlmap_in_container:
                run_info = self._run_sqlmap_in_container(
                    sqlmap_cmd=sqlmap_cmd,
                    task_dir=task_dir,
                    compose_project_path=project_path,
                    route_path=route_path,
                    screenshot_path=screenshot_path,
                    log_path=log_path,
                )
            else:
                run_info = self._run_sqlmap_direct(
                    sqlmap_cmd=sqlmap_cmd,
                    task_dir=task_dir,
                    screenshot_path=screenshot_path,
                    log_path=log_path,
                )

            result = {
                "executed": bool(run_info.get("started", False)),
                "screenshot_path": str(screenshot_path) if screenshot_path.exists() else None,
                "output_log": str(log_path) if log_path.exists() else None,
                "route_probe": route_probe,
                "command": run_info.get("command", ""),
                "runner": run_info.get("runner", "host"),
                "vulnerability_confirmed": self._check_vulnerability_confirmed(log_path),
                "return_code": run_info.get("return_code"),
                "timed_out": bool(run_info.get("timed_out", False)),
                "failure_reason": "" if run_info.get("started") else run_info.get("error", "sqlmap_not_started"),
            }
        except Exception as error:
            self.logger.error(f"SQLMap执行失败: {error}")
            result = {
                "executed": False,
                "error": str(error),
                "failure_reason": "sqlmap_exception",
                "route_probe": route_probe,
                "screenshot_path": None,
                "output_log": None,
                "vulnerability_confirmed": False,
                "return_code": None,
                "timed_out": False,
            }

        self._write_result(state, result)
        return {"output_path": str(self._get_output_path(state, "sqlmap_result.json")), "data": result}

    def _write_result(self, state: TaskState, result: Dict[str, Any]) -> None:
        output_path = self._get_output_path(state, "sqlmap_result.json")
        with open(output_path, "w", encoding="utf-8") as file:
            json.dump(result, file, ensure_ascii=False, indent=2)

    def _run_sqlmap_direct(
        self,
        sqlmap_cmd: str,
        task_dir: Path,
        screenshot_path: Path,
        log_path: Path,
    ) -> Dict[str, Any]:
        return self._run_command_with_screenshot(
            command=sqlmap_cmd,
            command_display=sqlmap_cmd,
            cwd=task_dir,
            screenshot_path=screenshot_path,
            log_path=log_path,
            shell=True,
            runner="host",
        )

    def _run_sqlmap_in_container(
        self,
        sqlmap_cmd: str,
        task_dir: Path,
        compose_project_path: Path,
        route_path: str,
        screenshot_path: Path,
        log_path: Path,
    ) -> Dict[str, Any]:
        if not compose_project_path.exists():
            raise RuntimeError(f"deploy项目目录不存在: {compose_project_path}")

        service_check = self._inspect_compose_services(compose_project_path)
        if not service_check.get("ok"):
            raise RuntimeError(f"docker compose服务检查失败: {service_check.get('error', 'unknown')}")
        if "sqlmap" not in {s.lower() for s in service_check.get("services", [])}:
            raise RuntimeError("docker compose中缺少sqlmap服务")

        container_req = task_dir / "test_container.txt"
        self._prepare_container_request_file(
            source_request=task_dir / "test.txt",
            output_request=container_req,
            route_path=route_path,
        )

        sqlmap_args = self._normalize_sqlmap_args(sqlmap_cmd)
        sqlmap_args = self._rewrite_request_file_arg(sqlmap_args, "/work/test_container.txt")
        if not any(arg in ("--batch",) for arg in sqlmap_args):
            sqlmap_args.append("--batch")

        docker_cmd: List[str] = [
            "docker",
            "compose",
            "run",
            "--rm",
            "-T",
            "-v",
            f"{str(task_dir.resolve())}:/work",
            "sqlmap",
            *sqlmap_args,
        ]

        return self._run_command_with_screenshot(
            command=docker_cmd,
            command_display=subprocess.list2cmdline(docker_cmd),
            cwd=compose_project_path,
            screenshot_path=screenshot_path,
            log_path=log_path,
            shell=False,
            runner="docker",
        )

    def _run_command_with_screenshot(
        self,
        command: Any,
        command_display: str,
        cwd: Path,
        screenshot_path: Path,
        log_path: Path,
        shell: bool,
        runner: str,
    ) -> Dict[str, Any]:
        self.logger.info(f"启动sqlmap进程({runner}): {command_display}")

        started = False
        timed_out = False
        return_code: Optional[int] = None
        merged_output = ""
        start_time = time.time()

        process = None
        try:
            process = subprocess.Popen(
                command,
                shell=shell,
                cwd=cwd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                encoding="utf-8",
                errors="replace",
            )
            started = True

            lines: List[str] = []
            if process.stdout:
                for line in process.stdout:
                    lines.append(line)
            process.wait(timeout=self.sqlmap_timeout)
            return_code = process.returncode
            merged_output = "".join(lines)
        except subprocess.TimeoutExpired:
            timed_out = True
            if process is not None:
                process.terminate()
                try:
                    process.wait(timeout=8)
                except Exception:
                    process.kill()
                return_code = process.returncode
        finally:
            duration = time.time() - start_time
            report_text = self._build_sqlmap_report_text(
                command=command_display,
                cwd=cwd,
                return_code=return_code,
                timed_out=timed_out,
                duration=duration,
                output_text=merged_output,
                runner=runner,
            )
            log_path.write_text(report_text, encoding="utf-8", errors="replace")
            self._render_text_screenshot(report_text, screenshot_path)

        return {
            "started": started,
            "timed_out": timed_out,
            "return_code": return_code,
            "command": command_display,
            "runner": runner,
        }

    def _normalize_sqlmap_args(self, sqlmap_cmd: str) -> List[str]:
        tokens = shlex.split(sqlmap_cmd, posix=False)
        if not tokens:
            raise RuntimeError("sqlmap命令为空")
        if "sqlmap" in tokens[0].lower():
            tokens = tokens[1:]
        return tokens

    def _rewrite_request_file_arg(self, args: List[str], container_request_path: str) -> List[str]:
        updated: List[str] = []
        skip_next = False
        replaced = False
        for idx, token in enumerate(args):
            if skip_next:
                skip_next = False
                continue
            if token == "-r" and idx + 1 < len(args):
                updated.extend(["-r", container_request_path])
                skip_next = True
                replaced = True
                continue
            if token.startswith("-r") and token != "-r":
                updated.append(f"-r{container_request_path}")
                replaced = True
                continue
            updated.append(token)
        if not replaced:
            updated.extend(["-r", container_request_path])
        return updated

    def _inspect_compose_services(self, project_path: Path) -> Dict[str, Any]:
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
                return {"ok": False, "services": [], "error": (result.stderr or result.stdout or "").strip()}
            services = [line.strip() for line in (result.stdout or "").splitlines() if line.strip()]
            return {"ok": True, "services": services, "error": ""}
        except Exception as error:
            return {"ok": False, "services": [], "error": str(error)}

    def _create_test_txt_from_command(
        self,
        cmd: str,
        base_url: str,
        route_path: str,
        output_path: Path,
    ) -> None:
        host = "127.0.0.1:18100"
        try:
            parsed = urlparse(base_url if "://" in base_url else f"http://{base_url}")
            if parsed.hostname and parsed.port:
                host = f"{parsed.hostname}:{parsed.port}"
        except Exception:
            pass

        path = route_path or "/admin/auth/roles"
        if not path.startswith("/"):
            path = f"/{path}"
        default_request = (
            f"POST {path} HTTP/1.1\n"
            f"Host: {host}\n"
            "Content-Type: application/x-www-form-urlencoded\n"
            "Cookie: laravel_session=placeholder\n"
            "\n"
            "_sort[column]=id&_sort[type]=asc&_sort[cast]=varchar"
        )
        output_path.write_text(default_request, encoding="utf-8", errors="replace")

    def _prepare_container_request_file(self, source_request: Path, output_request: Path, route_path: str) -> None:
        content = source_request.read_text(encoding="utf-8", errors="replace") if source_request.exists() else ""
        lines = content.splitlines() if content else []
        if not lines:
            lines = [f"POST {route_path} HTTP/1.1", "Host: app:8000", "Content-Type: application/x-www-form-urlencoded", "", "_sort[column]=id&_sort[type]=asc&_sort[cast]=varchar"]

        first = lines[0].strip() if lines else f"POST {route_path} HTTP/1.1"
        parts = first.split(" ")
        if len(parts) >= 3:
            method = parts[0]
            target = parts[1]
            version = parts[2]
            if target.startswith("http://") or target.startswith("https://"):
                parsed = urlparse(target)
                target = parsed.path or "/"
                if parsed.query:
                    target = f"{target}?{parsed.query}"
            lines[0] = f"{method} {target} {version}"

        host_replaced = False
        normalized: List[str] = []
        for line in lines:
            if line.lower().startswith("host:"):
                normalized.append("Host: app:8000")
                host_replaced = True
            else:
                normalized.append(line)
        if not host_replaced:
            normalized.insert(1, "Host: app:8000")

        output_request.write_text("\n".join(normalized).strip() + "\n", encoding="utf-8", errors="replace")

    def _extract_route_path(self, vulnerable_url: Any) -> str:
        raw = str(vulnerable_url or "").strip()
        if not raw:
            return "/admin/auth/roles"
        try:
            parsed = urlparse(raw if "://" in raw else f"http://127.0.0.1{raw}")
            path = parsed.path or "/"
            if parsed.query:
                path = f"{path}?{parsed.query}"
            if not path.startswith("/"):
                path = f"/{path}"
            return path
        except Exception:
            return "/admin/auth/roles"

    def _probe_route(self, base_url: str, route_path: str) -> Dict[str, Any]:
        normalized_base = base_url.strip() if isinstance(base_url, str) else ""
        if not normalized_base:
            normalized_base = "http://127.0.0.1:18100"
        if "://" not in normalized_base:
            normalized_base = f"http://{normalized_base}"
        route = route_path if route_path.startswith("/") else f"/{route_path}"
        url = f"{normalized_base.rstrip('/')}{route}"
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

    def _build_sqlmap_report_text(
        self,
        command: str,
        cwd: Path,
        return_code: Optional[int],
        timed_out: bool,
        duration: float,
        output_text: str,
        runner: str,
    ) -> str:
        header = [
            "=== SQLMAP EXECUTION REPORT ===",
            f"runner: {runner}",
            f"command: {command}",
            f"workdir: {cwd}",
            f"return_code: {return_code}",
            f"timed_out: {timed_out}",
            f"duration_seconds: {duration:.2f}",
            "",
            "=== SQLMAP RAW OUTPUT ===",
        ]
        return "\n".join(header) + "\n" + (output_text or "")

    def _render_text_screenshot(self, text: str, output_path: Path) -> None:
        from PIL import Image, ImageDraw, ImageFont

        raw_lines = (text or "").splitlines()[-140:]
        wrapped_lines: List[str] = []
        for raw in raw_lines:
            wrapped_lines.extend(textwrap.wrap(raw, width=150) or [""])

        try:
            font = ImageFont.truetype("consola.ttf", 18)
        except Exception:
            font = ImageFont.load_default()

        line_height = 24
        padding = 20
        width = 1800
        height = max(500, padding * 2 + line_height * len(wrapped_lines))
        img = Image.new("RGB", (width, height), color=(20, 20, 20))
        draw = ImageDraw.Draw(img)

        y = padding
        for line in wrapped_lines:
            draw.text((padding, y), line, font=font, fill=(230, 230, 230))
            y += line_height

        output_path.parent.mkdir(parents=True, exist_ok=True)
        img.save(output_path)

    def _check_vulnerability_confirmed(self, log_path: Path) -> bool:
        if not log_path.exists():
            return False
        try:
            content = log_path.read_text(encoding="utf-8", errors="ignore").lower()
        except Exception:
            return False
        keywords = [
            "is vulnerable",
            "confirmed",
            "injection point",
            "back-end dbms",
            "sql injection",
        ]
        return any(keyword in content for keyword in keywords)
