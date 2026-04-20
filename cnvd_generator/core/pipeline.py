#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""CNVD 报告生成流水线主控制器。"""

import time
from pathlib import Path
from typing import Any, Dict, Optional

from agents import (
    CVSSAgent,
    DeployAgent,
    GenerateAgent,
    GitHubSearchAgent,
    ParseAgent,
    SqlmapAgent,
)
from core.llm_client import LLMClient
from core.logger import PipelineLogger
from core.state import StateManager


class CNVDReportPipeline:
    """CNVD 报告流水线。"""

    def __init__(self, api_key: str = None):
        self.logger = PipelineLogger()
        self.state_manager = StateManager()
        self.llm = LLMClient(api_key=api_key)
        self.agents = {
            "parse": ParseAgent(self.llm),
            "github": GitHubSearchAgent(self.llm),
            "deploy": DeployAgent(self.llm),
            "cvss": CVSSAgent(self.llm),
            "sqlmap": SqlmapAgent(self.llm),
            "generate": GenerateAgent(self.llm),
        }
        self.logger.info("流水线初始化完成")

    def run(self, input_file: str, resume_from: Optional[str] = None) -> Dict[str, Any]:
        input_path = Path(input_file)
        if not input_path.exists():
            raise FileNotFoundError(f"输入文件不存在: {input_file}")

        report_name = input_path.stem
        full_step_order = ["parse", "github", "deploy", "cvss", "sqlmap", "generate"]
        effective_resume_from = resume_from

        state = self.state_manager.load_state(report_name)

        # 已完成任务：只有在输出文件确实存在且未指定 resume 时才直接跳过。
        if state and state.status == "completed":
            expected_output = Path(str(state.output_file or f"workspace/output/{report_name}.docx"))
            if effective_resume_from:
                self.logger.info(
                    f"任务 {report_name} 已完成，但指定了 resume-from={effective_resume_from}，将重新执行"
                )
            elif expected_output.exists():
                self.logger.info(f"任务 {report_name} 已完成，跳过")
                return {
                    "success": True,
                    "report_name": report_name,
                    "output_file": str(expected_output),
                    "message": "任务已完成",
                }
            else:
                self.logger.warning(
                    f"任务 {report_name} 状态为 completed，但输出文件不存在: {expected_output}，将从 generate 重新执行"
                )
                effective_resume_from = "generate"

        if not state:
            state = self.state_manager.create_task(str(input_path), report_name)
            self.logger.task_started(report_name, str(input_path))

        step_order = list(full_step_order)

        # resume-from：允许“重跑某一步及其后续步骤”。
        if effective_resume_from:
            if effective_resume_from not in full_step_order:
                raise ValueError(f"无效步骤: {effective_resume_from}")
            if not self.state_manager.can_resume_from(report_name, effective_resume_from):
                raise ValueError(f"无法从 {effective_resume_from} 恢复，请先完成前置步骤")

            resume_idx = full_step_order.index(effective_resume_from)
            for step_name in full_step_order[resume_idx:]:
                step_state = state.steps.get(step_name)
                if not step_state:
                    continue
                step_state.status = "pending"
                step_state.error = None
                step_state.output = None
                step_state.started_at = None
                step_state.completed_at = None
                step_state.duration = 0.0

            state.status = "running"
            state.output_file = None
            self.state_manager.save_state(state)

            step_order = full_step_order[resume_idx:]
            self.logger.info(f"从步骤 {effective_resume_from} 恢复执行")

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
                    agent.run(state)
                    step_duration = time.time() - step_start
                    self.logger.step_completed(report_name, step, step_duration)
                    state = self.state_manager.load_state(report_name)
                except Exception as error:
                    self.logger.error(f"步骤 {step} 执行失败: {error}")
                    self.state_manager.update_step(report_name, step, status="failed", error=str(error))
                    raise

            duration = time.time() - start_time
            output_file = f"workspace/output/{report_name}.docx"
            if not Path(output_file).exists():
                raise RuntimeError(f"生成步骤执行完成但未找到输出文件: {output_file}")
            state.status = "completed"
            state.output_file = output_file
            self.state_manager.save_state(state)
            self.logger.task_completed(report_name, output_file, duration)
            return {
                "success": True,
                "report_name": report_name,
                "output_file": output_file,
                "duration": duration,
            }
        except Exception as error:
            self.logger.task_failed(report_name, str(error))
            raise

    def batch_run(self, input_dir: str, output_dir: str = "workspace/output") -> list:
        input_path = Path(input_dir)
        if not input_path.exists():
            raise FileNotFoundError(f"输入目录不存在: {input_dir}")

        docx_files = list(input_path.glob("*.docx"))
        if not docx_files:
            self.logger.warning(f"目录中未找到 docx 文件: {input_dir}")
            return []

        self.logger.info(f"找到 {len(docx_files)} 个待处理文件")
        results = []
        for docx_file in docx_files:
            try:
                result = self.run(str(docx_file))
                results.append(result)
            except Exception as error:
                self.logger.error(f"处理 {docx_file.name} 失败: {error}")
                results.append({"success": False, "file": str(docx_file), "error": str(error)})
        return results

    def get_task_status(self, report_name: str) -> Optional[Dict[str, Any]]:
        state = self.state_manager.load_state(report_name)
        if not state:
            return None
        return {
            "report_name": state.report_name,
            "status": state.status,
            "created_at": state.created_at,
            "updated_at": state.updated_at,
            "steps": {
                name: {"status": step.status, "error": step.error}
                for name, step in state.steps.items()
            },
        }

    def list_tasks(self) -> list:
        return self.state_manager.list_tasks()
