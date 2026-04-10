#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CNVD报告生成流水线
主控制器，协调各Agent执行
"""

import time
from pathlib import Path
from typing import Optional, Dict, Any

from core.logger import PipelineLogger
from core.state import StateManager, TaskState
from core.llm_client import LLMClient
from agents import (
    ParseAgent,
    GitHubSearchAgent,
    DeployAgent,
    CVSSAgent,
    SqlmapAgent,
    GenerateAgent
)


class CNVDReportPipeline:
    """CNVD报告生成流水线"""

    def __init__(self, api_key: str = None):
        """
        初始化流水线

        Args:
            api_key: LLM API密钥（可选，默认从配置文件读取）
        """
        self.logger = PipelineLogger()
        self.state_manager = StateManager()

        # 初始化LLM客户端（从配置文件或参数读取）
        self.llm = LLMClient(api_key=api_key)

        # 初始化Agent
        self.agents = {
            'parse': ParseAgent(self.llm),
            'github': GitHubSearchAgent(self.llm),
            'deploy': DeployAgent(self.llm),
            'cvss': CVSSAgent(self.llm),
            'sqlmap': SqlmapAgent(self.llm),
            'generate': GenerateAgent(self.llm)
        }

        self.logger.info("流水线初始化完成")

    def run(self, input_file: str, resume_from: Optional[str] = None) -> Dict[str, Any]:
        """
        执行完整流程

        Args:
            input_file: 输入的可信代码库报告路径
            resume_from: 从指定步骤恢复（可选）

        Returns:
            执行结果
        """
        input_path = Path(input_file)
        if not input_path.exists():
            raise FileNotFoundError(f"输入文件不存在: {input_file}")

        report_name = input_path.stem

        # 检查是否已存在任务
        state = self.state_manager.load_state(report_name)

        if state and state.status == "completed":
            self.logger.info(f"任务 {report_name} 已完成，跳过")
            return {
                "success": True,
                "report_name": report_name,
                "output_file": state.output_file,
                "message": "任务已完成"
            }

        if not state:
            # 创建新任务
            state = self.state_manager.create_task(str(input_path), report_name)
            self.logger.task_started(report_name, str(input_path))

        # 确定执行步骤
        step_order = ['parse', 'github', 'deploy', 'cvss', 'sqlmap', 'generate']

        if resume_from:
            if resume_from not in step_order:
                raise ValueError(f"无效的步骤: {resume_from}")
            if not self.state_manager.can_resume_from(report_name, resume_from):
                raise ValueError(f"无法从 {resume_from} 恢复，请先完成前置步骤")
            step_order = step_order[step_order.index(resume_from):]
            self.logger.info(f"从步骤 {resume_from} 恢复执行")

        # 执行步骤
        start_time = time.time()

        try:
            for step in step_order:
                step_state = state.steps.get(step)

                if step_state and step_state.status == "completed":
                    self.logger.info(f"步骤 {step} 已完成，跳过")
                    continue

                self.logger.step_started(report_name, step)
                step_start = time.time()

                try:
                    agent = self.agents[step]
                    result = agent.run(state)

                    step_duration = time.time() - step_start
                    self.logger.step_completed(report_name, step, step_duration)

                    # 重新加载状态（Agent会更新状态）
                    state = self.state_manager.load_state(report_name)

                except Exception as e:
                    self.logger.error(f"步骤 {step} 执行失败: {e}")
                    self.state_manager.update_step(
                        report_name, step, status="failed", error=str(e)
                    )
                    raise

            # 更新任务状态为完成
            duration = time.time() - start_time
            output_file = f"workspace/output/{report_name}.docx"

            state.status = "completed"
            state.output_file = output_file
            self.state_manager.save_state(state)

            self.logger.task_completed(report_name, output_file, duration)

            return {
                "success": True,
                "report_name": report_name,
                "output_file": output_file,
                "duration": duration
            }

        except Exception as e:
            duration = time.time() - start_time
            self.logger.task_failed(report_name, str(e))
            raise

    def batch_run(self, input_dir: str, output_dir: str = "workspace/output") -> list:
        """
        批量处理

        Args:
            input_dir: 输入目录
            output_dir: 输出目录

        Returns:
            处理结果列表
        """
        input_path = Path(input_dir)
        if not input_path.exists():
            raise FileNotFoundError(f"输入目录不存在: {input_dir}")

        # 查找所有docx文件
        docx_files = list(input_path.glob("*.docx"))

        if not docx_files:
            self.logger.warning(f"目录中没有docx文件: {input_dir}")
            return []

        self.logger.info(f"找到 {len(docx_files)} 个待处理文件")

        results = []
        for docx_file in docx_files:
            try:
                result = self.run(str(docx_file))
                results.append(result)
            except Exception as e:
                self.logger.error(f"处理 {docx_file.name} 失败: {e}")
                results.append({
                    "success": False,
                    "file": str(docx_file),
                    "error": str(e)
                })

        return results

    def get_task_status(self, report_name: str) -> Optional[Dict[str, Any]]:
        """获取任务状态"""
        state = self.state_manager.load_state(report_name)
        if not state:
            return None

        return {
            "report_name": state.report_name,
            "status": state.status,
            "created_at": state.created_at,
            "updated_at": state.updated_at,
            "steps": {
                name: {
                    "status": step.status,
                    "error": step.error
                }
                for name, step in state.steps.items()
            }
        }

    def list_tasks(self) -> list:
        """列出所有任务"""
        return self.state_manager.list_tasks()
