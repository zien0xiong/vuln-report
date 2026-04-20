#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Agent日志系统
提供结构化日志记录和错误追踪
"""

import logging
import json
import os
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, Optional
import traceback

from core.state import StateManager


class AgentLogger:
    """Agent专用日志记录器"""

    def __init__(self, agent_name: str, task_id: str, log_dir: str = "workspace/logs"):
        self.agent_name = agent_name
        self.task_id = task_id
        self.state_manager = StateManager()
        self.safe_task_id = self.state_manager.normalize_report_name(task_id)
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(parents=True, exist_ok=True)

        # 创建logger
        self.logger = logging.getLogger(f"{agent_name}_{task_id}")
        self.logger.setLevel(logging.DEBUG)

        # 避免重复添加handler
        if not self.logger.handlers:
            # 文件handler - 按task和agent分开
            task_log_dir = self.state_manager.get_task_dir(task_id) / "logs"
            task_log_dir.mkdir(parents=True, exist_ok=True)

            fh = logging.FileHandler(
                task_log_dir / f"{agent_name}.log",
                encoding='utf-8'
            )
            fh.setLevel(logging.DEBUG)

            # 全局error日志
            error_fh = logging.FileHandler(
                self.log_dir / "error.log",
                encoding='utf-8'
            )
            error_fh.setLevel(logging.ERROR)

            # 控制台handler
            ch = logging.StreamHandler()
            ch.setLevel(logging.INFO)

            # 格式化
            formatter = logging.Formatter(
                '[%(asctime)s] [%(levelname)s] [%(name)s] %(message)s',
                datefmt='%Y-%m-%d %H:%M:%S'
            )
            fh.setFormatter(formatter)
            error_fh.setFormatter(formatter)
            ch.setFormatter(formatter)

            self.logger.addHandler(fh)
            self.logger.addHandler(error_fh)
            self.logger.addHandler(ch)

    def debug(self, msg: str):
        """记录调试信息"""
        self.logger.debug(msg)

    def info(self, msg: str):
        """记录信息"""
        self.logger.info(msg)

    def warning(self, msg: str):
        """记录警告"""
        self.logger.warning(msg)

    def error(self, msg: str, exc_info: bool = True):
        """记录错误"""
        self.logger.error(msg, exc_info=exc_info)

    def critical(self, msg: str):
        """记录严重错误"""
        self.logger.critical(msg)

    def log_tool_call(self, tool_name: str, params: Dict[str, Any],
                      duration: float, success: bool = True):
        """记录工具调用"""
        self.logger.info(
            f"[TOOL] {tool_name} | "
            f"params={json.dumps(params, ensure_ascii=False)} | "
            f"duration={duration:.2f}s | success={success}"
        )

    def log_llm_interaction(self, prompt: str, response: str,
                            tokens: Dict[str, int] = None):
        """记录大模型交互"""
        prompt_preview = prompt[:200] + "..." if len(prompt) > 200 else prompt
        response_preview = response[:200] + "..." if len(response) > 200 else response

        self.logger.info(
            f"[LLM] Prompt: {prompt_preview} | "
            f"Response: {response_preview}"
        )
        if tokens:
            self.logger.debug(f"[LLM] Tokens: {tokens}")

    def log_decision(self, decision: str, confidence: float, reason: str):
        """记录决策过程"""
        self.logger.info(
            f"[DECISION] {decision} | "
            f"confidence={confidence:.2f} | reason={reason}"
        )

    def log_error_with_context(self, error: Exception,
                               context: Dict[str, Any] = None,
                               suggestion: str = None):
        """记录带上下文的错误"""
        error_data = {
            "timestamp": datetime.now().isoformat(),
            "agent": self.agent_name,
            "task_id": self.task_id,
            "error_type": type(error).__name__,
            "error_message": str(error),
            "stack_trace": traceback.format_exc(),
            "context": context or {},
            "suggestion": suggestion
        }

        # 记录到专门的error日志文件
        error_log_path = self.log_dir / f"{self.safe_task_id}_errors.json"

        errors = []
        if error_log_path.exists():
            with open(error_log_path, 'r', encoding='utf-8') as f:
                errors = json.load(f)

        errors.append(error_data)

        with open(error_log_path, 'w', encoding='utf-8') as f:
            json.dump(errors, f, ensure_ascii=False, indent=2)

        self.logger.error(
            f"[ERROR] {error_data['error_type']}: {error_data['error_message']} | "
            f"Suggestion: {suggestion}"
        )

        return error_data

    def get_logs(self, level: str = None, tail: int = None) -> list:
        """获取日志内容"""
        log_file = self.state_manager.get_task_dir(self.task_id) / "logs" / f"{self.agent_name}.log"

        if not log_file.exists():
            return []

        with open(log_file, 'r', encoding='utf-8') as f:
            lines = f.readlines()

        if level:
            lines = [l for l in lines if f"[{level.upper()}]" in l]

        if tail:
            lines = lines[-tail:]

        return lines


class PipelineLogger:
    """流水线主控制器日志"""

    def __init__(self, log_dir: str = "workspace/logs"):
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(parents=True, exist_ok=True)

        self.logger = logging.getLogger("CNVDPipeline")
        self.logger.setLevel(logging.DEBUG)

        if not self.logger.handlers:
            fh = logging.FileHandler(
                self.log_dir / "cnvd_generator.log",
                encoding='utf-8'
            )
            fh.setLevel(logging.DEBUG)

            ch = logging.StreamHandler()
            ch.setLevel(logging.INFO)

            formatter = logging.Formatter(
                '[%(asctime)s] [%(levelname)s] [Pipeline] %(message)s',
                datefmt='%Y-%m-%d %H:%M:%S'
            )
            fh.setFormatter(formatter)
            ch.setFormatter(formatter)

            self.logger.addHandler(fh)
            self.logger.addHandler(ch)

    def info(self, msg: str):
        self.logger.info(msg)

    def warning(self, msg: str):
        self.logger.warning(msg)

    def error(self, msg: str):
        self.logger.error(msg)

    def task_started(self, task_id: str, input_file: str):
        """记录任务开始"""
        self.logger.info(f"[TASK_START] {task_id} | input={input_file}")

    def task_completed(self, task_id: str, output_file: str, duration: float):
        """记录任务完成"""
        self.logger.info(
            f"[TASK_COMPLETE] {task_id} | output={output_file} | duration={duration:.2f}s"
        )

    def task_failed(self, task_id: str, error: str):
        """记录任务失败"""
        self.logger.error(f"[TASK_FAILED] {task_id} | error={error}")

    def step_started(self, task_id: str, step: str):
        """记录步骤开始"""
        self.logger.info(f"[STEP_START] {task_id}/{step}")

    def step_completed(self, task_id: str, step: str, duration: float):
        """记录步骤完成"""
        self.logger.info(f"[STEP_COMPLETE] {task_id}/{step} | duration={duration:.2f}s")
