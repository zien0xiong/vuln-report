#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""SqlmapAgent - delegate sqlmap reproduction to Codex and persist evidence."""

from __future__ import annotations

import json
import re
import shutil
import subprocess
import threading
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
    """SQLMap 执行 Agent（通过 Codex 托管执行）"""

    def __init__(self, llm_client=None):
        super().__init__("SqlmapAgent", llm_client)
        sqlmap_cfg = config.get("sqlmap", {}) or {}
        deploy_cfg = config.get("deployment", {}) or {}

        self.sqlmap_timeout = int(sqlmap_cfg.get("timeout_seconds", 900))
        self.codex_timeout = int(sqlmap_cfg.get("codex_timeout_seconds", 2400))
        self.route_probe_timeout = int(sqlmap_cfg.get("route_probe_timeout_seconds", 12))
        self.sqlmap_in_container = bool(deploy_cfg.get("sqlmap_in_container", True))
        self.auth_cfg = sqlmap_cfg.get("auth", {}) or {}
        strategy_cfg = sqlmap_cfg.get("strategy", {}) or {}
        self.command_policy = str(strategy_cfg.get("command_policy", "reference_only")).strip().lower() or "reference_only"
        self.success_rule = str(strategy_cfg.get("success_rule", "parameter_and_evidence")).strip().lower() or "parameter_and_evidence"
        self.invalid_json_retry_once = bool(strategy_cfg.get("invalid_json_retry_once", True))
        self.codex_run_limit = 1 + (1 if self.invalid_json_retry_once else 0)

    def _execute(self, state: TaskState) -> Dict[str, Any]:
        parsed_data = self._load_previous_output(state, "parse", "parsed.json")
        deployment_data = self._load_previous_output(state, "deploy", "deployment.json")

        if not parsed_data:
            raise RuntimeError("找不到 ParseAgent 的输出")

        deployment = deployment_data.get("deployment", {}) if isinstance(deployment_data, dict) else {}
        base_url = self._normalize_base_url(str(deployment.get("base_url", "")).strip())
        project_path = Path(str(deployment.get("project_path", "")).strip() or ".")
        route_path = self._extract_route_path(parsed_data.get("vulnerable_url", "")) or "/admin/auth/roles"
        self.logger.info(
            f"SqlmapAgent 输入就绪 | base_url={base_url} | route={route_path} | project_path={project_path}"
        )

        sqlmap_cmd = str(parsed_data.get("sqlmap_command", "")).strip()
        if not sqlmap_cmd:
            sqlmap_cmd = self._build_default_sqlmap_command()
        self.logger.info(f"SqlmapAgent 命令模板: {sqlmap_cmd}")

        task_dir = self.state_manager.get_task_dir(state.report_name)
        task_dir.mkdir(parents=True, exist_ok=True)
        sqlmap_dir = task_dir / "05_sqlmap"
        sqlmap_dir.mkdir(parents=True, exist_ok=True)

        result_log_path = sqlmap_dir / "sqlmap_output.txt"
        result_screenshot_path = sqlmap_dir / "sqlmap_result.png"
        request_path = task_dir / "test.txt"
        container_request_path = task_dir / "test_container.txt"

        route_probe = self._probe_route(base_url, route_path)
        self.logger.info(
            f"SqlmapAgent 路由探测 | url={route_probe.get('url')} | status={route_probe.get('status_code')} | reachable={route_probe.get('reachable')}"
        )
        if not route_probe.get("reachable"):
            result = self._build_failed_result(
                route_probe=route_probe,
                failure_reason="route_unreachable",
                error=f"目标路由不可达: {route_probe.get('error', 'unknown')}",
            )
            self._write_result(state, result)
            return {"output_path": str(self._get_output_path(state, "sqlmap_result.json")), "data": result}

        if int(route_probe.get("status_code") or 0) == 404:
            report_text = (
                "=== SQLMAP EXECUTION REPORT ===\n"
                f"failure_reason: route_404\n"
                f"url: {route_probe.get('url')}\n"
                "detail: deploy step did not expose expected route for vulnerability reproduction.\n"
            )
            result_log_path.write_text(report_text, encoding="utf-8", errors="replace")
            self._render_text_screenshot(
                report_text,
                result_screenshot_path,
                command=sqlmap_cmd,
                cwd=project_path if project_path.exists() else task_dir,
            )
            result = self._build_failed_result(
                route_probe=route_probe,
                failure_reason="route_404",
                error="目标路由返回 404，无法执行 sqlmap 复现",
                output_log=str(result_log_path),
                screenshot_path=str(result_screenshot_path),
            )
            self._write_result(state, result)
            return {"output_path": str(self._get_output_path(state, "sqlmap_result.json")), "data": result}

        auth_profile = self._build_auth_profile(base_url, parsed_data)
        self.logger.info(
            f"SqlmapAgent 认证配置 | login_path={auth_profile.get('login_path')} | "
            f"username_field={auth_profile.get('username_field')} | password_field={auth_profile.get('password_field')} | "
            f"user_set={bool(auth_profile.get('username'))} | source={auth_profile.get('source')}"
        )
        if auth_profile["missing_fields"]:
            result = self._build_failed_result(
                route_probe=route_probe,
                failure_reason="missing_auth_config",
                error=f"缺少登录配置: {', '.join(auth_profile['missing_fields'])}",
            )
            self._write_result(state, result)
            return {"output_path": str(self._get_output_path(state, "sqlmap_result.json")), "data": result}

        base_dir = project_path if project_path.exists() else task_dir
        target_parameter = self._infer_target_parameter(sqlmap_cmd, parsed_data)
        self.logger.info(
            f"SqlmapAgent target parameter hint: {target_parameter or '(none)'} | "
            f"command_policy={self.command_policy} | mode=prompt_first | invalid_json_retry_once={self.invalid_json_retry_once}"
        )

        attempt_summaries: List[Dict[str, Any]] = []
        codex_history: List[Dict[str, Any]] = []
        selected: Optional[Dict[str, Any]] = None

        max_runs = self.codex_run_limit
        for attempt_index in range(1, max_runs + 1):
            strategy_note = "prompt_first_primary" if attempt_index == 1 else "prompt_first_retry_invalid_json"
            attempt_log_path = result_log_path if attempt_index == 1 else sqlmap_dir / f"sqlmap_output_attempt{attempt_index}.txt"
            attempt_screenshot_path = (
                result_screenshot_path if attempt_index == 1 else sqlmap_dir / f"sqlmap_result_attempt{attempt_index}.png"
            )
            codex_result = self._run_sqlmap_via_codex(
                task_dir=task_dir,
                project_path=project_path,
                parsed_data=parsed_data,
                deployment=deployment,
                base_url=base_url,
                route_path=route_path,
                sqlmap_command=sqlmap_cmd,
                auth_profile=auth_profile,
                request_path=request_path,
                container_request_path=container_request_path,
                result_log_path=attempt_log_path,
                result_screenshot_path=attempt_screenshot_path,
                attempt_index=attempt_index,
                max_attempts=max_runs,
                strategy_note=strategy_note,
                target_parameter=target_parameter,
                previous_attempts=attempt_summaries,
                command_reference=sqlmap_cmd,
            )
            self.logger.info(
                f"SqlmapAgent Codex attempt#{attempt_index}/{max_runs} | status={codex_result.get('status')} | "
                f"return_code={codex_result.get('return_code')} | failure_reason={codex_result.get('failure_reason')}"
            )

            resolved_log_path = self._resolve_output_path(
                codex_result.get("log_path", ""),
                default_path=attempt_log_path,
                base_dir=base_dir,
            )
            resolved_screenshot_path = self._resolve_output_path(
                codex_result.get("screenshot_path", ""),
                default_path=attempt_screenshot_path,
                base_dir=base_dir,
            )

            log_content = ""
            if resolved_log_path.exists():
                log_content = self._read_text_file(resolved_log_path)
            else:
                log_content = str(codex_result.get("raw_output", "")).strip()
                if log_content:
                    resolved_log_path.parent.mkdir(parents=True, exist_ok=True)
                    resolved_log_path.write_text(log_content, encoding="utf-8", errors="replace")
            clean_log = self._strip_ansi(log_content)

            positive_snippets = self._extract_positive_evidence_snippets(clean_log)
            heuristic_snippets = self._extract_heuristic_evidence_snippets(clean_log)
            negative_snippets = self._extract_negative_evidence_snippets(clean_log)
            evidence_keywords = self._merge_evidence_keywords(clean_log, codex_result.get("evidence_keywords", []))
            target_parameter_match = self._is_target_parameter_match(clean_log, target_parameter, codex_result)
            attempt_reasoning = str(codex_result.get("attempt_reasoning", "")).strip() or strategy_note

            vulnerability_confirmed = bool(codex_result.get("vulnerability_confirmed", False))
            confirmation_source = str(codex_result.get("confirmation_source", "") or "").strip().lower()
            if confirmation_source not in {"sqlmap", "side_effect", "none"}:
                confirmation_source = "sqlmap" if vulnerability_confirmed else "none"

            # Guard against known false-positive pattern in sqlmap output.
            if negative_snippets and not positive_snippets and confirmation_source != "side_effect":
                vulnerability_confirmed = False
                confirmation_source = "none"
                if not str(codex_result.get("failure_reason", "")).strip():
                    codex_result["failure_reason"] = "negative_evidence_detected"

            evidence_level = str(codex_result.get("evidence_level", "") or "").strip().lower()
            if evidence_level not in {"confirmed", "heuristic", "none"}:
                if vulnerability_confirmed and positive_snippets:
                    evidence_level = "confirmed"
                elif heuristic_snippets:
                    evidence_level = "heuristic"
                else:
                    evidence_level = "none"

            evidence_snippets = [
                str(item).strip()
                for item in (codex_result.get("evidence_snippets", []) if isinstance(codex_result.get("evidence_snippets"), list) else [])
                if str(item).strip()
            ]
            if not evidence_snippets:
                if evidence_level == "confirmed":
                    evidence_snippets = positive_snippets
                elif evidence_level == "heuristic":
                    evidence_snippets = heuristic_snippets
                else:
                    evidence_snippets = self._extract_evidence_snippets(clean_log)

            negative_evidence_snippets = [
                str(item).strip()
                for item in (
                    codex_result.get("negative_evidence_snippets", [])
                    if isinstance(codex_result.get("negative_evidence_snippets"), list)
                    else []
                )
                if str(item).strip()
            ]
            if not negative_evidence_snippets:
                negative_evidence_snippets = negative_snippets

            screenshot_text = self._select_screenshot_text(clean_log, preferred=evidence_level)
            self._render_text_screenshot(
                screenshot_text or clean_log or "sqlmap output is empty",
                resolved_screenshot_path,
                command=str(codex_result.get("command", sqlmap_cmd)),
                cwd=base_dir,
            )

            attempt_status = str(codex_result.get("status", "failed")).strip().lower()
            if attempt_status not in {"success", "failed"}:
                attempt_status = "failed"
            if vulnerability_confirmed:
                attempt_status = "success"

            attempt_summary = {
                "attempt": attempt_index,
                "strategy": strategy_note,
                "attempt_reasoning": attempt_reasoning,
                "command": str(codex_result.get("command", sqlmap_cmd)),
                "executed": bool(codex_result.get("executed", False)),
                "status": attempt_status,
                "confirmed": vulnerability_confirmed,
                "confirmation_source": confirmation_source,
                "evidence_level": evidence_level,
                "target_parameter": target_parameter,
                "tested_parameter": str(codex_result.get("tested_parameter", "") or ""),
                "target_parameter_match": target_parameter_match,
                "strong_evidence": bool(vulnerability_confirmed and evidence_level == "confirmed"),
                "failure_reason": str(codex_result.get("failure_reason", "")),
                "output_log": str(resolved_log_path) if resolved_log_path.exists() else None,
                "screenshot_path": str(resolved_screenshot_path) if resolved_screenshot_path.exists() else None,
                "evidence_keywords": evidence_keywords,
                "evidence_snippets": evidence_snippets,
                "negative_evidence_snippets": negative_evidence_snippets,
                "hint_evidence_snippets": heuristic_snippets,
            }
            attempt_summaries.append(attempt_summary)
            if isinstance(codex_result.get("history"), list):
                codex_history.extend(codex_result.get("history", []))

            selected = {
                "codex_result": codex_result,
                "resolved_log_path": resolved_log_path,
                "resolved_screenshot_path": resolved_screenshot_path,
                "evidence_keywords": evidence_keywords,
                "vulnerability_confirmed": vulnerability_confirmed,
                "target_parameter_match": target_parameter_match,
                "strong_evidence": bool(vulnerability_confirmed and evidence_level == "confirmed"),
                "attempt_reasoning": attempt_reasoning,
                "evidence_snippets": evidence_snippets,
                "negative_evidence_snippets": negative_evidence_snippets,
                "hint_evidence_snippets": heuristic_snippets,
                "confirmation_source": confirmation_source,
                "evidence_level": evidence_level,
                "strategy": strategy_note,
            }

            should_retry = (
                attempt_index < max_runs
                and str(codex_result.get("failure_reason", "")).strip().lower() == "invalid_codex_json"
            )
            if should_retry:
                self.logger.warning("SqlmapAgent retrying once because Codex output JSON was invalid")
                continue
            break

        selected = selected or {
            "codex_result": {},
            "resolved_log_path": result_log_path,
            "resolved_screenshot_path": result_screenshot_path,
            "evidence_keywords": [],
            "vulnerability_confirmed": False,
            "target_parameter_match": False,
            "strong_evidence": False,
            "attempt_reasoning": "",
            "evidence_snippets": [],
            "negative_evidence_snippets": [],
            "hint_evidence_snippets": [],
            "confirmation_source": "none",
            "evidence_level": "none",
            "strategy": "",
        }
        codex_result = selected["codex_result"]
        resolved_log_path = selected["resolved_log_path"]
        resolved_screenshot_path = selected["resolved_screenshot_path"]
        evidence_keywords = selected["evidence_keywords"]
        vulnerability_confirmed = bool(selected["vulnerability_confirmed"])
        target_parameter_match = bool(selected.get("target_parameter_match", False))
        strong_evidence = bool(selected.get("strong_evidence", False))
        attempt_reasoning = str(selected.get("attempt_reasoning", "") or "")
        evidence_snippets = selected.get("evidence_snippets", [])
        negative_evidence_snippets = selected.get("negative_evidence_snippets", [])
        hint_evidence_snippets = selected.get("hint_evidence_snippets", [])
        confirmation_source = str(selected.get("confirmation_source", "none") or "none")
        evidence_level = str(selected.get("evidence_level", "none") or "none")

        failure_reason = str(codex_result.get("failure_reason", "")).strip()
        status = "success" if vulnerability_confirmed else "failed"
        if vulnerability_confirmed:
            failure_reason = ""
        elif not failure_reason:
            failure_reason = "no_injection_evidence_or_parameter_mismatch"

        result = {
            "executed": any(bool(item.get("executed")) for item in attempt_summaries),
            "execution_mode": "codex",
            "route_probe": route_probe,
            "command": str(codex_result.get("command", sqlmap_cmd)),
            "runner": "codex",
            "status": status,
            "auth_used": bool(codex_result.get("auth_used", True)),
            "vulnerability_confirmed": vulnerability_confirmed,
            "confirmation_source": confirmation_source,
            "evidence_level": evidence_level,
            "success_rule": self.success_rule,
            "target_parameter": target_parameter,
            "target_parameter_match": target_parameter_match,
            "strong_evidence": strong_evidence,
            "evidence_keywords": evidence_keywords,
            "evidence_snippets": evidence_snippets,
            "negative_evidence_snippets": negative_evidence_snippets,
            "hint_evidence_snippets": hint_evidence_snippets,
            "attempt_limit": max_runs,
            "attempt_reasoning": attempt_reasoning,
            "confidence": self._estimate_confidence(vulnerability_confirmed, evidence_keywords),
            "return_code": codex_result.get("return_code"),
            "timed_out": bool(codex_result.get("timed_out", False)),
            "failure_reason": failure_reason,
            "error": str(codex_result.get("error", "")),
            "notes": str(codex_result.get("notes", "")),
            "output_log": str(resolved_log_path) if resolved_log_path.exists() else None,
            "screenshot_path": str(resolved_screenshot_path) if resolved_screenshot_path.exists() else None,
            "attempts": attempt_summaries,
            "codex_history": codex_history,
        }
        self.logger.info(
            f"SqlmapAgent final result | status={result.get('status')} | confirmed={result.get('vulnerability_confirmed')} | "
            f"param_match={result.get('target_parameter_match')} | output_log={result.get('output_log')} | screenshot={result.get('screenshot_path')}"
        )
        self._write_result(state, result)
        return {"output_path": str(self._get_output_path(state, "sqlmap_result.json")), "data": result}

    def _run_sqlmap_via_codex(
        self,
        task_dir: Path,
        project_path: Path,
        parsed_data: Dict[str, Any],
        deployment: Dict[str, Any],
        base_url: str,
        route_path: str,
        sqlmap_command: str,
        auth_profile: Dict[str, Any],
        request_path: Path,
        container_request_path: Path,
        result_log_path: Path,
        result_screenshot_path: Path,
        attempt_index: int = 1,
        max_attempts: int = 1,
        strategy_note: str = "",
        target_parameter: str = "",
        previous_attempts: Optional[List[Dict[str, Any]]] = None,
        command_reference: str = "",
    ) -> Dict[str, Any]:
        codex_path = self._detect_codex_executable()
        if not codex_path:
            return {
                "status": "failed",
                "executed": False,
                "failure_reason": "codex_not_found",
                "error": "codex executable not found in PATH",
                "history": [],
            }

        working_root = project_path.resolve() if project_path.exists() else task_dir.resolve()
        sqlmap_dir = result_log_path.parent
        codex_stdout = sqlmap_dir / "codex_sqlmap_stdout.log"
        codex_stderr = sqlmap_dir / "codex_sqlmap_stderr.log"
        codex_last_msg = sqlmap_dir / "codex_sqlmap_last_message.txt"

        prompt = self._build_codex_sqlmap_prompt(
            base_url=base_url,
            route_path=route_path,
            parsed_data=parsed_data,
            deployment=deployment,
            sqlmap_command=sqlmap_command,
            command_reference=command_reference or sqlmap_command,
            auth_profile=auth_profile,
            request_path=request_path.resolve(),
            container_request_path=container_request_path.resolve(),
            result_log_path=result_log_path.resolve(),
            result_screenshot_path=result_screenshot_path.resolve(),
            prefer_container=self.sqlmap_in_container,
            sqlmap_timeout=self.sqlmap_timeout,
            attempt_index=attempt_index,
            max_attempts=max_attempts,
            strategy_note=strategy_note,
            target_parameter=target_parameter,
            previous_attempts=previous_attempts or [],
        )
        self.logger.info(
            f"SqlmapAgent 准备启动 Codex | workdir={working_root} | codex_timeout={self.codex_timeout}s | sqlmap_timeout={self.sqlmap_timeout}s"
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
            str(codex_last_msg),
            "-",
        ]
        self.logger.info(
            f"SqlmapAgent Codex命令: {str(codex_path)} exec --json -C {working_root} -o {codex_last_msg}"
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

            def _reader(pipe: Any, sink: List[str], is_stdout: bool) -> None:
                try:
                    for line in iter(pipe.readline, ""):
                        if not line:
                            break
                        sink.append(line)
                        codex_events["last_event_time"] = time.time()
                        if is_stdout:
                            self._collect_codex_events(line, codex_events)
                finally:
                    try:
                        pipe.close()
                    except Exception:
                        pass

            assert proc.stdout is not None and proc.stderr is not None
            t_out = threading.Thread(target=_reader, args=(proc.stdout, stdout_lines, True), daemon=True)
            t_err = threading.Thread(target=_reader, args=(proc.stderr, stderr_lines, False), daemon=True)
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
                    self.logger.warning(f"SqlmapAgent Codex timeout after {self.codex_timeout}s")
                    break

                if codex_events.get("turn_completed"):
                    idle_seconds = now - float(codex_events.get("last_event_time", now))
                    if idle_seconds >= 3:
                        self.logger.info("SqlmapAgent Codex early-exit: turn.completed observed and idle")
                        break

                idle_seconds = now - float(codex_events.get("last_event_time", now))
                if idle_seconds >= 20 and codex_last_msg.exists():
                    mtime = codex_last_msg.stat().st_mtime
                    if mtime != last_checked_message_mtime:
                        last_checked_message_mtime = mtime
                        candidate = codex_last_msg.read_text(encoding="utf-8", errors="replace")
                        if self._can_recover_early(candidate, result_log_path):
                            early_message_text = candidate
                            self.logger.info("SqlmapAgent Codex early-exit: recoverable last message detected")
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
                "executed": False,
                "failure_reason": "codex_exec_exception",
                "error": str(error),
                "timed_out": False,
                "history": [],
            }

        duration = time.time() - start
        codex_stdout.write_text(stdout_text or "", encoding="utf-8", errors="replace")
        codex_stderr.write_text(stderr_text or "", encoding="utf-8", errors="replace")

        message_text = early_message_text or str(codex_events.get("last_agent_message", "") or "")
        if codex_last_msg.exists():
            file_message = codex_last_msg.read_text(encoding="utf-8", errors="replace")
            if file_message.strip():
                message_text = file_message
        if not message_text.strip():
            message_text = self._extract_last_agent_message_from_jsonl(stdout_text)

        parsed = self._parse_codex_result(message_text, stdout_text)
        parsed["executed"] = True
        parsed["timed_out"] = timed_out
        parsed["return_code"] = return_code
        parsed["raw_output"] = (parsed.get("raw_output") or "") + "\n" + (stderr_text or "")
        parsed["history"] = [
            {
                "event": "codex_exec",
                "exit_code": return_code,
                "duration": duration,
                "timed_out": timed_out,
                "stdout_log": str(codex_stdout),
                "stderr_log": str(codex_stderr),
                "last_message_file": str(codex_last_msg),
            }
        ]
        if timed_out and not parsed.get("failure_reason"):
            parsed["failure_reason"] = "codex_timeout"
        if timed_out and not parsed.get("error"):
            parsed["error"] = f"codex timed out after {self.codex_timeout}s"
        return parsed

    def _build_codex_sqlmap_prompt(
        self,
        base_url: str,
        route_path: str,
        parsed_data: Dict[str, Any],
        deployment: Dict[str, Any],
        sqlmap_command: str,
        command_reference: str,
        auth_profile: Dict[str, Any],
        request_path: Path,
        container_request_path: Path,
        result_log_path: Path,
        result_screenshot_path: Path,
        prefer_container: bool,
        sqlmap_timeout: int,
        attempt_index: int = 1,
        max_attempts: int = 1,
        strategy_note: str = "",
        target_parameter: str = "",
        previous_attempts: Optional[List[Dict[str, Any]]] = None,
    ) -> str:
        product_name = str(parsed_data.get("product_name", "") or "").strip()
        vulnerability_type = str(parsed_data.get("vulnerability_type", "") or "").strip()
        principle = str(parsed_data.get("vulnerability_principle", "")).strip()
        vulnerable_files = parsed_data.get("vulnerable_files", [])
        if isinstance(vulnerable_files, list):
            vulnerable_files_text = ", ".join([str(item).strip() for item in vulnerable_files if str(item).strip()]) or "(n/a)"
        else:
            vulnerable_files_text = str(vulnerable_files or "").strip() or "(n/a)"
        reproduction_steps = parsed_data.get("reproduction_steps", [])
        if isinstance(reproduction_steps, list):
            steps_text = "\n".join([f"- {str(item)}" for item in reproduction_steps if str(item).strip()])
        else:
            steps_text = str(reproduction_steps or "").strip()

        compose_project = str(deployment.get("project_path", "")).strip()
        services = deployment.get("compose_services", [])
        services_text = ", ".join([str(s) for s in services]) if isinstance(services, list) else ""
        previous_text = self._format_previous_attempts(previous_attempts or [])
        policy_hint = {
            "reference_only": "Use report SQLMap command as reference only. You must decide the command autonomously.",
            "near_replay_first": "Prefer a near-replay of report command first, then adapt autonomously if needed.",
            "ignore_reference": "Ignore report SQLMap command and build your own command from vulnerability details.",
        }.get(self.command_policy, "Use report SQLMap command as reference only. You must decide the command autonomously.")

        return f"""
You are an autonomous security testing operator. Execute ONE sqlmap reproduction attempt and output strict JSON only.
Do not ask questions. Start immediately.

Target base URL: {base_url}
Target route path: {route_path}
Product: {product_name}
Vulnerability type: {vulnerability_type}
Vulnerable files from report: {vulnerable_files_text}
Target parameter from report: {target_parameter or "(infer from report context and request body)"}
Current attempt: {attempt_index}/{max_attempts}
Attempt strategy note: {strategy_note or "n/a"}
SQLMap timeout seconds: {sqlmap_timeout}

Auth context:
- Login URL path: {auth_profile["login_path"]}
- Login username field: {auth_profile["username_field"]}
- Login password field: {auth_profile["password_field"]}
- Login csrf field: {auth_profile["csrf_field"]}
- Username: {auth_profile["username"]}
- Password: {auth_profile["password"]}

Deployment context:
- Project path: {compose_project}
- Compose services: {services_text}
- Prefer container sqlmap: {"true" if prefer_container else "false"}

Report SQLMap command (REFERENCE ONLY, not mandatory):
{command_reference}

Previous attempts summary:
{previous_text}

Vulnerability principle:
{principle}

Reproduction steps from report:
{steps_text}

Required artifacts (must be created/updated):
1) request file: {request_path}
2) container request file: {container_request_path}
3) sqlmap log: {result_log_path}
4) screenshot image (PNG/JPG): {result_screenshot_path}

Hard requirements:
1) Generic workflow for arbitrary reports. Do NOT hardcode product-specific parameter names.
2) {policy_hint}
3) Prompt-first execution: you autonomously choose commands and verification actions based on report + deployment context.
4) Your goal is to detect the injection point described in the report. Prefer commands that focus on report target parameter and endpoint.
5) All shell commands MUST be non-interactive. Never wait for human input.
6) On Windows PowerShell, do NOT use `curl` alias. Use `curl.exe` OR `Invoke-WebRequest -UseBasicParsing -Confirm:$false`.
7) If an interactive prompt appears, rerun immediately with non-interactive flags/options.
8) If container service `sqlmap` exists, prefer container run. If container command fails, quickly fallback to another runnable command.
9) Write full sqlmap stdout/stderr into sqlmap log file.
10) Generate screenshot with this priority:
   - priority 1: explicit vulnerability evidence
   - priority 2: heuristic line like "might be injectable"
   - priority 3: failure reason lines
11) Set vulnerability_confirmed=true ONLY when explicit evidence exists and not contradicted by false-positive outcomes:
   - "identified the following injection point(s)"
   - "parameter ... is vulnerable"
   - "appears to be injectable"
12) If sqlmap says "false positive" / "does not seem to be injectable" / "all tested parameters do not appear to be injectable", then vulnerability_confirmed MUST be false unless you have stronger independent proof.
13) Do NOT treat only "back-end DBMS is ..." as sufficient proof.
14) Final output MUST be one JSON object:
{{
  "status": "success" | "failed",
  "auth_used": true | false,
  "command": "executed sqlmap command",
  "return_code": 0,
  "vulnerability_confirmed": true | false,
   "confirmation_source": "sqlmap" | "side_effect" | "none",
   "evidence_level": "confirmed" | "heuristic" | "none",
  "tested_parameter": "parameter_name_or_empty",
  "parameter_hit": true | false,
  "evidence_keywords": ["..."],
  "evidence_snippets": ["short decisive lines"],
   "negative_evidence_snippets": ["negative lines if any"],
   "attempt_reasoning": "what you changed and why in this attempt",
  "log_path": "absolute path",
  "screenshot_path": "absolute path",
  "failure_reason": "short_code_or_empty",
  "notes": "short summary",
  "raw_output": "optional short tail"
}}
"""

    def _parse_codex_result(self, message_text: str, stdout_text: str) -> Dict[str, Any]:
        blob = self._extract_json_blob(message_text) or self._extract_json_blob(stdout_text)
        if not isinstance(blob, dict):
            return {
                "status": "failed",
                "auth_used": False,
                "command": "",
                "return_code": None,
                "vulnerability_confirmed": False,
                "confirmation_source": "none",
                "evidence_level": "none",
                "evidence_keywords": [],
                "negative_evidence_snippets": [],
                "log_path": "",
                "screenshot_path": "",
                "failure_reason": "invalid_codex_json",
                "notes": "",
                "raw_output": message_text or stdout_text,
                "error": "Failed to parse codex sqlmap result JSON",
            }

        status_raw = str(blob.get("status", "")).strip().lower()
        if status_raw in {"success", "running", "completed", "ok"}:
            status = "success"
        else:
            status = "failed"

        evidence_keywords: List[str] = []
        for item in blob.get("evidence_keywords", []) if isinstance(blob.get("evidence_keywords"), list) else []:
            if isinstance(item, str) and item.strip():
                evidence_keywords.append(item.strip())

        confirmation_source = str(blob.get("confirmation_source", "")).strip().lower()
        if confirmation_source not in {"sqlmap", "side_effect", "none"}:
            confirmation_source = "sqlmap" if bool(blob.get("vulnerability_confirmed", False)) else "none"

        evidence_level = str(blob.get("evidence_level", "")).strip().lower()
        if evidence_level not in {"confirmed", "heuristic", "none"}:
            evidence_level = "confirmed" if bool(blob.get("vulnerability_confirmed", False)) else "none"

        return {
            "status": status,
            "auth_used": bool(blob.get("auth_used", False)),
            "command": str(blob.get("command", "")).strip(),
            "return_code": blob.get("return_code"),
            "vulnerability_confirmed": bool(blob.get("vulnerability_confirmed", False)),
            "confirmation_source": confirmation_source,
            "evidence_level": evidence_level,
            "tested_parameter": str(blob.get("tested_parameter", "")).strip(),
            "parameter_hit": bool(blob.get("parameter_hit", False)),
            "evidence_keywords": evidence_keywords,
            "evidence_snippets": [
                str(item).strip()
                for item in blob.get("evidence_snippets", [])
                if isinstance(item, str) and str(item).strip()
            ]
            if isinstance(blob.get("evidence_snippets"), list)
            else [],
            "negative_evidence_snippets": [
                str(item).strip()
                for item in blob.get("negative_evidence_snippets", [])
                if isinstance(item, str) and str(item).strip()
            ]
            if isinstance(blob.get("negative_evidence_snippets"), list)
            else [],
            "attempt_reasoning": str(blob.get("attempt_reasoning", "")).strip(),
            "log_path": str(blob.get("log_path", "")).strip(),
            "screenshot_path": str(blob.get("screenshot_path", "")).strip(),
            "failure_reason": str(blob.get("failure_reason", "")).strip(),
            "notes": str(blob.get("notes", "")).strip(),
            "raw_output": str(blob.get("raw_output", "")).strip(),
            "error": str(blob.get("error", "")).strip(),
        }

    def _infer_target_parameter(self, sqlmap_command: str, parsed_data: Dict[str, Any]) -> str:
        command = str(sqlmap_command or "")
        match = re.search(r"(?:^|\s)-p\s+(\"[^\"]+\"|'[^']+'|[^\s]+)", command)
        if match:
            value = str(match.group(1) or "").strip().strip("\"'")
            if value:
                return value.split(",")[0].strip()

        principle = str(parsed_data.get("vulnerability_principle", "") or "")
        for token in re.findall(r"`([^`]+)`", principle):
            candidate = str(token).strip()
            if candidate and re.search(r"[A-Za-z0-9_\[\]\.-]{2,}", candidate):
                if candidate.lower() not in {"select", "where", "from", "order"}:
                    return candidate

        vulnerable_url = str(parsed_data.get("vulnerable_url", "") or "")
        if "?" in vulnerable_url:
            query = vulnerable_url.split("?", 1)[1]
            first = query.split("&", 1)[0].split("=", 1)[0].strip()
            if first:
                return first
        return ""

    def _has_strong_evidence(self, keywords: List[str]) -> bool:
        strong = {"is_vulnerable", "appears_injectable", "injection_point", "parameter_injectable"}
        return any(item in strong for item in keywords)

    def _merge_evidence_keywords(self, log_content: str, codex_keywords: Any) -> List[str]:
        merged = self._collect_evidence_keywords(log_content)
        low = str(log_content or "").lower()
        allowed = {"is_vulnerable", "appears_injectable", "injection_point", "back_end_dbms", "parameter_injectable"}

        if isinstance(codex_keywords, list):
            for item in codex_keywords:
                key = str(item or "").strip()
                if not key or key not in allowed:
                    continue
                if key == "injection_point" and not re.search(
                    r"identified the following injection point(?:\(s\))?",
                    low,
                    flags=re.IGNORECASE,
                ):
                    continue
                if key == "appears_injectable" and "appears to be injectable" not in low:
                    continue
                if key == "is_vulnerable" and "is vulnerable" not in low:
                    continue
                if key == "back_end_dbms" and "back-end dbms is" not in low and "back end dbms is" not in low:
                    continue
                if key not in merged:
                    merged.append(key)

        if "all tested parameters do not appear to be injectable" in low and not self._has_strong_evidence(merged):
            return []
        if merged == ["back_end_dbms"]:
            return []
        return merged

    def _format_previous_attempts(self, attempts: List[Dict[str, Any]]) -> str:
        if not attempts:
            return "- none"

        lines: List[str] = []
        for item in attempts[-5:]:
            command = str(item.get("command", "") or "").strip()
            if len(command) > 180:
                command = f"{command[:177]}..."
            lines.append(
                f"- attempt#{item.get('attempt')}: confirmed={bool(item.get('confirmed'))}, "
                f"param_match={bool(item.get('target_parameter_match'))}, "
                f"strong_evidence={bool(item.get('strong_evidence'))}, "
                f"failure_reason={item.get('failure_reason') or ''}, command={command}"
            )
        return "\n".join(lines)

    def _normalize_parameter(self, value: str) -> str:
        text = str(value or "").strip().strip("\"'`")
        return text.lower()

    def _is_target_parameter_match(self, log_content: str, target_parameter: str, codex_result: Dict[str, Any]) -> bool:
        target = self._normalize_parameter(target_parameter)
        if not target:
            return True

        tested_parameter = self._normalize_parameter(str(codex_result.get("tested_parameter", "") or ""))
        if tested_parameter:
            if tested_parameter == target:
                return True
            # codex explicitly reported another parameter
            if bool(codex_result.get("parameter_hit", False)):
                return False

        if bool(codex_result.get("parameter_hit", False)):
            return True

        low = str(log_content or "").lower()
        patterns = (
            rf"parameter ['\"`]?{re.escape(target)}['\"`]?",
            rf"on (?:post|get|cookie|uri) parameter ['\"`]?{re.escape(target)}['\"`]?",
            rf"\b-p\s+['\"`]?(?:[^'\"`\s,]+,)*{re.escape(target)}(?:,[^'\"`\s,]+)*['\"`]?",
        )
        return any(re.search(pattern, low, flags=re.IGNORECASE) for pattern in patterns)

    def _extract_evidence_snippets(self, log_content: str, limit: int = 6) -> List[str]:
        snippets = (
            self._extract_positive_evidence_snippets(log_content, limit=limit)
            or self._extract_heuristic_evidence_snippets(log_content, limit=limit)
            or self._extract_negative_evidence_snippets(log_content, limit=limit)
        )
        if snippets:
            return snippets

        fallback: List[str] = []
        for raw_line in str(log_content or "").splitlines():
            line = raw_line.strip()
            if not line:
                continue
            if "[INFO]" in line or "[WARNING]" in line or "[ERROR]" in line or "[CRITICAL]" in line:
                fallback.append(line)
            if len(fallback) >= limit:
                break
        return fallback

    def _extract_positive_evidence_snippets(self, log_content: str, limit: int = 6) -> List[str]:
        patterns = [
            r"identified the following injection point(?:\(s\))?",
            r"parameter ['\"`]?.+?['\"`]?\s+is vulnerable",
            r"\bappears to be injectable\b",
        ]
        return self._extract_lines_by_patterns(log_content, patterns=patterns, limit=limit)

    def _extract_negative_evidence_snippets(self, log_content: str, limit: int = 6) -> List[str]:
        patterns = [
            r"false positive or unexploitable injection point detected",
            r"does not seem to be injectable",
            r"all tested parameters do not appear to be injectable",
        ]
        return self._extract_lines_by_patterns(log_content, patterns=patterns, limit=limit)

    def _extract_heuristic_evidence_snippets(self, log_content: str, limit: int = 6) -> List[str]:
        patterns = [
            r"heuristic \(basic\) test shows .* might be injectable",
            r"\bmight be injectable\b",
        ]
        return self._extract_lines_by_patterns(log_content, patterns=patterns, limit=limit)

    def _extract_lines_by_patterns(self, log_content: str, patterns: List[str], limit: int = 6) -> List[str]:
        snippets: List[str] = []
        for raw_line in str(log_content or "").splitlines():
            line = raw_line.strip()
            if not line:
                continue
            low = line.lower()
            if any(re.search(pattern, low, flags=re.IGNORECASE) for pattern in patterns):
                snippets.append(line)
            if len(snippets) >= limit:
                break
        return snippets

    def _select_screenshot_text(self, log_content: str, preferred: str = "confirmed") -> str:
        lines = [line.rstrip("\r") for line in str(log_content or "").splitlines()]
        if not lines:
            return ""

        mode = str(preferred or "none").strip().lower()
        pattern_groups: Dict[str, List[str]] = {
            "confirmed": [
                r"identified the following injection point(?:\(s\))?",
                r"parameter ['\"`]?.+?['\"`]?\s+is vulnerable",
                r"\bappears to be injectable\b",
            ],
            "heuristic": [
                r"heuristic \(basic\) test shows .* might be injectable",
                r"\bmight be injectable\b",
            ],
            "none": [
                r"false positive or unexploitable injection point detected",
                r"does not seem to be injectable",
                r"all tested parameters do not appear to be injectable",
                r"\btimeout\b",
                r"\bconnection timed out\b",
                r"\broute_404\b",
            ],
        }
        search_order: List[str]
        if mode == "confirmed":
            search_order = ["confirmed", "heuristic", "none"]
        elif mode == "heuristic":
            search_order = ["heuristic", "confirmed", "none"]
        else:
            search_order = ["none", "heuristic", "confirmed"]

        anchor_idx: List[int] = []
        chosen_group = "none"
        for group in search_order:
            anchors = []
            for idx, raw in enumerate(lines):
                low = str(raw).lower()
                if any(re.search(pattern, low, flags=re.IGNORECASE) for pattern in pattern_groups[group]):
                    anchors.append(idx)
            if anchors:
                anchor_idx = anchors
                chosen_group = group
                break

        if not anchor_idx:
            tail = lines[-120:]
            return "\n".join(tail)

        before = 4
        after = 10 if chosen_group == "confirmed" else 6
        first = max(0, anchor_idx[0] - before)
        last = min(len(lines) - 1, anchor_idx[-1] + after)
        if last - first > 160:
            last = first + 160
        excerpt = lines[first : last + 1]
        return "\n".join(excerpt)

    def _collect_codex_events(self, line: str, tracker: Dict[str, Any]) -> None:
        raw = str(line or "").strip()
        if not raw or not raw.startswith("{"):
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
        if item.get("type") != "agent_message":
            return
        text = str(item.get("text", "")).strip()
        if text:
            tracker["last_agent_message"] = text

    def _can_recover_early(self, candidate_message: str, result_log_path: Path) -> bool:
        message_text = str(candidate_message or "").strip()
        if not message_text:
            return False

        blob = self._extract_json_blob(candidate_message)
        if isinstance(blob, dict):
            status = str(blob.get("status", "")).strip().lower()
            has_status = status in {"success", "failed", "ok", "completed", "running"}
            if has_status:
                return True

        if result_log_path.exists():
            low = message_text.lower()
            if '"status"' in low and ("success" in low or "failed" in low):
                return True
        return False

    def _build_auth_profile(self, base_url: str, parsed_data: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        report_auth = parsed_data.get("auth", {}) if isinstance(parsed_data, dict) else {}
        if not isinstance(report_auth, dict):
            report_auth = {}

        def normalize_value(value: Any) -> str:
            if value is None:
                return ""
            text = str(value).strip()
            if text.lower() in {"none", "null", "nan", "n/a"}:
                return ""
            return text

        def pick(field: str, default: str = "") -> tuple[str, str]:
            report_value = normalize_value(report_auth.get(field, ""))
            if report_value:
                return report_value, "report"
            config_value = normalize_value(self.auth_cfg.get(field, ""))
            if config_value:
                return config_value, "config"
            return normalize_value(default), "default"

        username, username_source = pick("username")
        password, password_source = pick("password")
        login_path, login_path_source = pick("login_path", "/admin/auth/login")
        username_field, username_field_source = pick("username_field", "username")
        password_field, password_field_source = pick("password_field", "password")
        csrf_field, csrf_field_source = pick("csrf_field", "_token")

        missing_fields: List[str] = []
        if not username:
            missing_fields.append("sqlmap.auth.username")
        if not password:
            missing_fields.append("sqlmap.auth.password")

        login_path = self._normalize_login_path(login_path, base_url)

        source_map = {
            "login_path": login_path_source,
            "username": username_source,
            "password": password_source,
            "username_field": username_field_source,
            "password_field": password_field_source,
            "csrf_field": csrf_field_source,
        }
        primary_source = "report" if any(v == "report" for v in source_map.values()) else "config"

        return {
            "base_url": base_url,
            "login_path": login_path,
            "username": username,
            "password": password,
            "username_field": username_field,
            "password_field": password_field,
            "csrf_field": csrf_field,
            "missing_fields": missing_fields,
            "source": primary_source,
            "source_map": source_map,
        }

    def _normalize_login_path(self, login_path: str, base_url: str) -> str:
        path = str(login_path or "").strip()
        if not path:
            return "/admin/auth/login"
        if path.startswith("http://") or path.startswith("https://"):
            try:
                parsed = urlparse(path)
                path = parsed.path or "/admin/auth/login"
                if parsed.query:
                    path = f"{path}?{parsed.query}"
            except Exception:
                path = "/admin/auth/login"
        if not path.startswith("/"):
            path = f"/{path}"
        return path

    def _build_failed_result(
        self,
        route_probe: Dict[str, Any],
        failure_reason: str,
        error: str,
        output_log: Optional[str] = None,
        screenshot_path: Optional[str] = None,
    ) -> Dict[str, Any]:
        return {
            "executed": False,
            "execution_mode": "codex",
            "route_probe": route_probe,
            "command": "",
            "runner": "codex",
            "status": "failed",
            "auth_used": False,
            "vulnerability_confirmed": False,
            "confirmation_source": "none",
            "evidence_level": "none",
            "success_rule": self.success_rule,
            "target_parameter": "",
            "target_parameter_match": False,
            "strong_evidence": False,
            "evidence_keywords": [],
            "evidence_snippets": [],
            "negative_evidence_snippets": [],
            "hint_evidence_snippets": [],
            "attempt_limit": self.codex_run_limit,
            "attempt_reasoning": "",
            "confidence": 0.0,
            "return_code": None,
            "timed_out": False,
            "failure_reason": failure_reason,
            "error": error,
            "notes": "",
            "output_log": output_log,
            "screenshot_path": screenshot_path,
            "codex_history": [],
        }

    def _write_result(self, state: TaskState, result: Dict[str, Any]) -> None:
        output_path = self._get_output_path(state, "sqlmap_result.json")
        with open(output_path, "w", encoding="utf-8") as file:
            json.dump(result, file, ensure_ascii=False, indent=2)

    def _build_default_sqlmap_command(self) -> str:
        return (
            "sqlmap -r test.txt "
            "--threads=4 --level=5 --risk=3 --batch "
            "--flush-session --fresh-queries --technique=BEUST --parse-errors"
        )

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
                    candidate = Path(line.strip())
                    if candidate.exists():
                        candidates.append(candidate)
                for path in candidates:
                    if path.suffix.lower() in {".exe", ".cmd", ".bat"}:
                        return path
                if candidates:
                    return candidates[0]
        except Exception:
            pass

        for name in ("codex.cmd", "codex.exe", "codex.bat", "codex"):
            found = shutil.which(name)
            if found:
                return Path(found)
        return None

    def _collect_evidence_keywords(self, text: str) -> List[str]:
        low = str(text or "").lower()
        patterns = {
            "is_vulnerable": r"\bis vulnerable\b",
            "appears_injectable": r"\bappears to be injectable\b",
            "injection_point": r"identified the following injection point(?:\(s\))?",
            "back_end_dbms": r"\bback-?end dbms\s+is\b",
            "parameter_injectable": r"parameter ['\"`]?.+?['\"`]? is vulnerable",
        }

        hits: List[str] = []
        for name, pattern in patterns.items():
            if re.search(pattern, low):
                hits.append(name)

        # "forcing back-end DBMS to user defined value" 不是漏洞确认依据，避免误报
        if "back_end_dbms" in hits and "forcing back-end dbms" in low:
            has_strong = any(name in hits for name in ("is_vulnerable", "appears_injectable", "injection_point", "parameter_injectable"))
            if not has_strong:
                hits = [name for name in hits if name != "back_end_dbms"]

        has_negative = (
            "false positive or unexploitable injection point detected" in low
            or "does not seem to be injectable" in low
            or "all tested parameters do not appear to be injectable" in low
        )
        negative_only = has_negative
        if negative_only and not any(name in hits for name in ("is_vulnerable", "injection_point", "back_end_dbms", "parameter_injectable")):
            return []
        return hits

    def _estimate_confidence(self, confirmed: bool, evidence_keywords: List[str]) -> float:
        if not confirmed:
            return 0.0
        score = min(0.99, 0.60 + len(evidence_keywords) * 0.10)
        return round(score, 2)

    def _resolve_output_path(self, raw_path: str, default_path: Path, base_dir: Path) -> Path:
        raw = str(raw_path or "").strip()
        if not raw:
            return default_path
        candidate = Path(raw)
        if candidate.is_absolute():
            return candidate
        return (base_dir / candidate).resolve()

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

    def _normalize_base_url(self, base_url: str) -> str:
        raw = str(base_url or "").strip()
        if not raw:
            return "http://127.0.0.1:18100"
        if "://" not in raw:
            raw = f"http://{raw}"
        try:
            parsed = urlparse(raw)
            scheme = parsed.scheme or "http"
            host = parsed.hostname or "127.0.0.1"
            port = parsed.port or 18100
            return f"{scheme}://{host}:{port}"
        except Exception:
            return "http://127.0.0.1:18100"

    def _probe_route(self, base_url: str, route_path: str) -> Dict[str, Any]:
        route = route_path if route_path.startswith("/") else f"/{route_path}"
        url = f"{base_url.rstrip('/')}{route}"
        try:
            response = requests.get(url, timeout=self.route_probe_timeout, allow_redirects=False)
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

    def _extract_json_blob(self, text: str) -> Optional[Dict[str, Any]]:
        if not text:
            return None
        source = str(text).strip()
        if not source:
            return None

        try:
            data = json.loads(source)
            if isinstance(data, dict):
                return data
        except Exception:
            pass

        for raw_line in reversed(source.splitlines()):
            line = raw_line.strip()
            if not (line.startswith("{") and line.endswith("}")):
                continue
            try:
                data = json.loads(line)
                if isinstance(data, dict):
                    return data
            except Exception:
                continue

        start = source.find("{")
        end = source.rfind("}")
        if start >= 0 and end > start:
            fragment = source[start : end + 1]
            try:
                data = json.loads(fragment)
                if isinstance(data, dict):
                    return data
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

    def _render_text_screenshot(
        self,
        text: str,
        output_path: Path,
        command: str = "",
        cwd: Optional[Path] = None,
    ) -> None:
        from PIL import Image, ImageDraw, ImageFont

        clean_text = self._strip_ansi(text or "")
        raw_output_lines = [line.rstrip("\r") for line in clean_text.splitlines()]
        if not raw_output_lines:
            raw_output_lines = [""]
        evidence_block = self._find_sqlmap_evidence_block(raw_output_lines)

        font = None
        for font_path in (
            "C:/Windows/Fonts/CascadiaMono.ttf",
            "C:/Windows/Fonts/consola.ttf",
            "C:/Windows/Fonts/msyh.ttc",
        ):
            try:
                font = ImageFont.truetype(font_path, 20)
                break
            except Exception:
                continue
        if font is None:
            font = ImageFont.load_default()

        width = 1600
        height = 900
        title_bar_h = 44
        outer_bg = (28, 28, 28)
        terminal_bg = (0, 0, 0)
        padding_x = 20
        padding_y = 16
        img = Image.new("RGB", (width, height), color=outer_bg)
        draw = ImageDraw.Draw(img)

        # 窗口标题栏
        draw.rectangle([(0, 0), (width, title_bar_h)], fill=(46, 46, 46))
        draw.text((18, 12), "Command Prompt - sqlmap", font=font, fill=(236, 236, 236))
        draw.text((width - 96, 12), "—  □  ✕", font=font, fill=(220, 220, 220))

        # 终端内容区域
        content_top = title_bar_h
        draw.rectangle([(0, content_top), (width, height)], fill=terminal_bg)

        char_bbox = draw.textbbox((0, 0), "M", font=font)
        char_w = max(8, char_bbox[2] - char_bbox[0])
        line_h = max(22, (char_bbox[3] - char_bbox[1]) + 6)
        max_cols = max(60, (width - padding_x * 2) // char_w)
        max_rows = max(20, (height - content_top - padding_y * 2) // line_h)

        workdir = cwd.resolve() if isinstance(cwd, Path) else Path.cwd().resolve()
        prompt = f"{workdir}>"
        cmd_line = f"{prompt} {command}".strip() if command else prompt

        prefix_lines = [
            "Microsoft Windows [Version 10.0.19045.0]",
            "(c) Microsoft Corporation. All rights reserved.",
            "",
            cmd_line,
        ]

        wrapped_prefix: List[tuple[str, bool, str]] = []
        for raw in prefix_lines:
            for line in (textwrap.wrap(raw, width=max_cols, break_long_words=False) or [""]):
                wrapped_prefix.append((line, False, "prefix"))

        wrapped_output: List[tuple[str, bool, str]] = []
        for idx, raw in enumerate(raw_output_lines):
            in_block = bool(evidence_block and evidence_block[0] <= idx <= evidence_block[1])
            has_signal = self._is_sqlmap_evidence_line(raw)
            mark = in_block or has_signal
            for line in (textwrap.wrap(raw, width=max_cols, break_long_words=False) or [""]):
                wrapped_output.append((line, mark, "output"))

        visible_lines: List[tuple[str, bool, str]]
        if len(wrapped_prefix) + len(wrapped_output) <= max_rows:
            visible_lines = wrapped_prefix + wrapped_output
        else:
            reserve = min(len(wrapped_prefix), max(3, max_rows // 4))
            tail_slots = max_rows - reserve - 1
            if tail_slots <= 0:
                visible_lines = (wrapped_prefix + wrapped_output)[-max_rows:]
            else:
                # 优先保证可见区域覆盖 SQL 注入证据块
                highlight_idx = [i for i, item in enumerate(wrapped_output) if item[1]]
                if highlight_idx and tail_slots > 0:
                    block_start = min(highlight_idx)
                    block_end = max(highlight_idx)
                    focus_size = min(tail_slots, max(8, block_end - block_start + 1 + 6))
                    center = (block_start + block_end) // 2
                    start = max(0, center - focus_size // 2)
                    end = min(len(wrapped_output), start + focus_size)
                    if end - start < focus_size:
                        start = max(0, end - focus_size)
                    focused = wrapped_output[start:end]
                    remaining = tail_slots - len(focused)
                    if remaining > 0:
                        prefix_tail = wrapped_output[max(0, start - remaining):start]
                        focused = prefix_tail + focused
                    visible_lines = wrapped_prefix[:reserve] + [("...", False, "ellipsis")] + focused[-tail_slots:]
                else:
                    visible_lines = wrapped_prefix[:reserve] + [("...", False, "ellipsis")] + wrapped_output[-tail_slots:]

        y = content_top + padding_y
        highlight_rows: List[int] = []
        for idx, (line, marked, source_kind) in enumerate(visible_lines):
            if idx == 3 and line.strip():  # 命令行输入高亮
                fill = (150, 220, 150)
            elif source_kind == "ellipsis":
                fill = (180, 180, 180)
            elif "[WARNING]" in line.upper():
                fill = (240, 210, 120)
            elif "[ERROR]" in line.upper():
                fill = (255, 140, 140)
            elif "[INFO]" in line.upper():
                fill = (120, 210, 150)
            else:
                fill = (230, 230, 230)
            draw.text((padding_x, y), line, font=font, fill=fill)
            if marked:
                highlight_rows.append(idx)
            y += line_h

        if highlight_rows:
            top_row = min(highlight_rows)
            bottom_row = max(highlight_rows)
            box_top = content_top + padding_y + top_row * line_h - 6
            box_bottom = content_top + padding_y + (bottom_row + 1) * line_h + 6
            box_left = max(2, padding_x - 12)
            box_right = width - max(2, padding_x - 12)
            draw.rectangle(
                [(box_left, box_top), (box_right, box_bottom)],
                outline=(255, 70, 70),
                width=4,
            )

        # 末行光标
        cursor_y = min(height - padding_y - line_h, y)
        draw.text((padding_x, cursor_y), "_", font=font, fill=(230, 230, 230))

        output_path.parent.mkdir(parents=True, exist_ok=True)
        img.save(output_path)

    def _is_sqlmap_evidence_line(self, line: str) -> bool:
        low = str(line or "").lower()
        if "forcing back-end dbms" in low:
            return False
        patterns = (
            r"identified the following injection point",
            r"parameter ['\"`]?.+?['\"`]?(?:\s*\(post\)|\s*\(get\)|\s*\(cookie\)|)\s+is vulnerable",
            r"\bis vulnerable\b",
            r"\bappears to be injectable\b",
            r"heuristic \(basic\) test shows .* might be injectable",
            r"^\s*type:\s",
            r"^\s*title:\s",
            r"^\s*payload:\s",
            r"\bback-?end dbms\s+is\b",
        )
        return any(re.search(pattern, low) for pattern in patterns)

    def _find_sqlmap_evidence_block(self, lines: List[str]) -> Optional[tuple[int, int]]:
        if not lines:
            return None
        first = -1
        last = -1
        for idx, line in enumerate(lines):
            if self._is_sqlmap_evidence_line(line):
                if first < 0:
                    first = idx
                last = idx
        if first < 0:
            return None

        # 向后拓展，尽量覆盖 Type/Title/Payload 等明确信息
        end = last
        for idx in range(last + 1, min(len(lines), last + 16)):
            line = str(lines[idx] or "").strip()
            if not line:
                end = idx
                continue
            low = line.lower()
            if self._is_sqlmap_evidence_line(line):
                end = idx
                continue
            if low.startswith("[") and ("[info]" in low or "[warning]" in low or "[error]" in low):
                # 新日志段开头，停止扩展
                break
            if line.startswith("do you want"):
                break
            end = idx
        return first, max(first, end)

    def _strip_ansi(self, text: str) -> str:
        if not text:
            return ""
        ansi_pattern = re.compile(r"\x1B[@-_][0-?]*[ -/]*[@-~]")
        return ansi_pattern.sub("", str(text))

    def _read_text_file(self, path: Path) -> str:
        if not path.exists():
            return ""
        data = path.read_bytes()
        if not data:
            return ""

        # BOM 检测
        if data.startswith(b"\xff\xfe") or data.startswith(b"\xfe\xff"):
            try:
                return data.decode("utf-16")
            except Exception:
                pass
        if data.startswith(b"\xef\xbb\xbf"):
            try:
                return data.decode("utf-8-sig")
            except Exception:
                pass

        # 若存在大量 \x00，通常为 UTF-16
        null_ratio = data.count(0) / max(len(data), 1)
        if null_ratio > 0.15:
            for enc in ("utf-16", "utf-16-le", "utf-16-be"):
                try:
                    return data.decode(enc)
                except Exception:
                    continue

        for enc in ("utf-8", "gb18030", "latin-1"):
            try:
                return data.decode(enc)
            except Exception:
                continue

        return data.decode("utf-8", errors="replace")
