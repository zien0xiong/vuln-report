#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Agent基类
所有Agent的抽象基类
"""

import time
from abc import ABC, abstractmethod
from typing import Dict, Any, Optional
from pathlib import Path

from core.logger import AgentLogger
from core.state import StateManager, TaskState
from core.llm_client import LLMClient


class BaseAgent(ABC):
    """Agent基类"""

    def __init__(self, name: str, llm_client: LLMClient = None):
        self.name = name
        self.llm = llm_client
        self.state_manager = StateManager()

    def run(self, state: TaskState) -> Dict[str, Any]:
        """
        执行Agent任务

        Args:
            state: 当前任务状态

        Returns:
            执行结果字典
        """
        report_name = state.report_name

        # 创建logger
        self.logger = AgentLogger(self.name, report_name)

        self.logger.info(f"=== {self.name} 开始执行 ===")

        # 更新步骤状态为进行中
        self.state_manager.update_step(
            report_name, self._get_step_name(),
            status="in_progress"
        )

        start_time = time.time()

        try:
            # 执行具体逻辑
            result = self._execute(state)

            duration = time.time() - start_time

            # 更新步骤状态为完成
            self.state_manager.update_step(
                report_name, self._get_step_name(),
                status="completed",
                output=result.get("output_path"),
                duration=duration
            )

            self.logger.info(f"=== {self.name} 执行完成 ({duration:.2f}s) ===")

            return {
                "success": True,
                "result": result,
                "duration": duration
            }

        except Exception as e:
            duration = time.time() - start_time

            self.logger.log_error_with_context(
                e,
                context={"agent": self.name, "task": report_name},
                suggestion="请检查日志获取详细信息"
            )

            # 更新步骤状态为失败
            self.state_manager.update_step(
                report_name, self._get_step_name(),
                status="failed",
                error=str(e),
                duration=duration
            )

            self.logger.error(f"=== {self.name} 执行失败 ({duration:.2f}s) ===")

            raise

    @abstractmethod
    def _execute(self, state: TaskState) -> Dict[str, Any]:
        """
        具体的执行逻辑，子类必须实现

        Args:
            state: 当前任务状态

        Returns:
            执行结果
        """
        pass

    def _get_step_name(self) -> str:
        """获取步骤名称（用于状态管理）"""
        step_names = {
            "ParseAgent": "parse",
            "GitHubSearchAgent": "github",
            "DeployAgent": "deploy",
            "CVSSAgent": "cvss",
            "SqlmapAgent": "sqlmap",
            "GenerateAgent": "generate"
        }
        return step_names.get(self.name, self.name.lower())

    def _get_output_path(self, state: TaskState, filename: str) -> Path:
        """获取输出文件路径"""
        return self.state_manager.get_step_output_path(
            state.report_name, self._get_step_name(), filename
        )

    def _load_previous_output(self, state: TaskState, step: str,
                              filename: str) -> Optional[Dict]:
        """加载之前步骤的输出"""
        output_path = self.state_manager.get_step_output_path(
            state.report_name, step, filename
        )

        if not output_path.exists():
            return None

        import json
        with open(output_path, 'r', encoding='utf-8') as f:
            return json.load(f)


class ToolCall:
    """工具调用封装"""

    def __init__(self, name: str, params: Dict[str, Any]):
        self.name = name
        self.params = params
        self.result = None
        self.duration = 0.0

    def execute(self, func) -> Any:
        """执行工具函数"""
        import time

        start = time.time()
        try:
            self.result = func(**self.params)
            return self.result
        finally:
            self.duration = time.time() - start
