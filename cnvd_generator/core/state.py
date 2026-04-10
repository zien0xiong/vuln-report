#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
状态管理系统
管理任务状态和Agent间的数据传递
"""

import json
import os
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, Optional, List
from dataclasses import dataclass, asdict, field


@dataclass
class StepState:
    """单个步骤的状态"""
    status: str = "pending"  # pending, in_progress, completed, failed
    output: Optional[str] = None
    error: Optional[str] = None
    started_at: Optional[str] = None
    completed_at: Optional[str] = None
    duration: float = 0.0


@dataclass
class TaskState:
    """任务整体状态"""
    report_name: str
    input_file: str
    created_at: str = field(default_factory=lambda: datetime.now().isoformat())
    updated_at: str = field(default_factory=lambda: datetime.now().isoformat())
    status: str = "pending"  # pending, running, completed, failed
    steps: Dict[str, StepState] = field(default_factory=dict)
    output_file: Optional[str] = None

    def __post_init__(self):
        # 初始化所有步骤
        if not self.steps:
            self.steps = {
                "parse": StepState(),
                "github": StepState(),
                "deploy": StepState(),
                "cvss": StepState(),
                "sqlmap": StepState(),
                "generate": StepState()
            }


class StateManager:
    """状态管理器"""

    def __init__(self, workspace_dir: str = "workspace"):
        self.workspace_dir = Path(workspace_dir)
        self.workspace_dir.mkdir(parents=True, exist_ok=True)

    def _get_task_dir(self, report_name: str) -> Path:
        """获取任务目录"""
        # 清理report_name中的特殊字符
        safe_name = "".join(c for c in report_name if c.isalnum() or c in ('-', '_'))
        return self.workspace_dir / safe_name

    def _get_state_file(self, report_name: str) -> Path:
        """获取状态文件路径"""
        return self._get_task_dir(report_name) / "state.json"

    def create_task(self, input_file: str, report_name: str = None) -> TaskState:
        """创建新任务"""
        if not report_name:
            report_name = Path(input_file).stem

        task_dir = self._get_task_dir(report_name)
        task_dir.mkdir(parents=True, exist_ok=True)

        # 创建子目录
        for subdir in ["01_parse", "02_github", "03_sourcecode",
                       "04_cvss", "05_sqlmap", "logs"]:
            (task_dir / subdir).mkdir(exist_ok=True)

        state = TaskState(
            report_name=report_name,
            input_file=input_file
        )

        self.save_state(state)
        return state

    def load_state(self, report_name: str) -> Optional[TaskState]:
        """加载任务状态"""
        state_file = self._get_state_file(report_name)

        if not state_file.exists():
            return None

        with open(state_file, 'r', encoding='utf-8') as f:
            data = json.load(f)

        # 转换steps为StepState对象
        steps = {}
        for step_name, step_data in data.get('steps', {}).items():
            steps[step_name] = StepState(**step_data)
        data['steps'] = steps

        return TaskState(**data)

    def save_state(self, state: TaskState):
        """保存任务状态"""
        state.updated_at = datetime.now().isoformat()

        state_file = self._get_state_file(state.report_name)

        # 转换为字典
        data = asdict(state)

        with open(state_file, 'w', encoding='utf-8') as f:
            json.dump(data, f, ensure_ascii=False, indent=2)

    def update_step(self, report_name: str, step: str,
                    status: str = None, output: str = None,
                    error: str = None, duration: float = None):
        """更新步骤状态"""
        state = self.load_state(report_name)
        if not state:
            raise ValueError(f"Task not found: {report_name}")

        step_state = state.steps.get(step)
        if not step_state:
            raise ValueError(f"Step not found: {step}")

        if status:
            step_state.status = status
            if status == "in_progress" and not step_state.started_at:
                step_state.started_at = datetime.now().isoformat()
            elif status in ("completed", "failed"):
                step_state.completed_at = datetime.now().isoformat()

        if output:
            step_state.output = output

        if error:
            step_state.error = error

        if duration is not None:
            step_state.duration = duration

        # 更新整体状态
        self._update_task_status(state)

        self.save_state(state)
        return state

    def _update_task_status(self, state: TaskState):
        """根据步骤状态更新任务整体状态"""
        statuses = [s.status for s in state.steps.values()]

        if all(s == "completed" for s in statuses):
            state.status = "completed"
        elif any(s == "failed" for s in statuses):
            state.status = "failed"
        elif any(s == "in_progress" for s in statuses):
            state.status = "running"
        else:
            state.status = "pending"

    def get_step_output_path(self, report_name: str, step: str,
                             filename: str) -> Path:
        """获取步骤输出文件路径"""
        task_dir = self._get_task_dir(report_name)

        step_dirs = {
            "parse": "01_parse",
            "github": "02_github",
            "deploy": "03_sourcecode",
            "cvss": "04_cvss",
            "sqlmap": "05_sqlmap"
        }

        step_dir = step_dirs.get(step, step)
        return task_dir / step_dir / filename

    def list_tasks(self) -> List[Dict[str, Any]]:
        """列出所有任务"""
        tasks = []

        for item in self.workspace_dir.iterdir():
            if item.is_dir():
                state_file = item / "state.json"
                if state_file.exists():
                    state = self.load_state(item.name)
                    if state:
                        tasks.append({
                            "report_name": state.report_name,
                            "status": state.status,
                            "created_at": state.created_at,
                            "updated_at": state.updated_at
                        })

        return sorted(tasks, key=lambda x: x["updated_at"], reverse=True)

    def can_resume_from(self, report_name: str, step: str) -> bool:
        """检查是否可以从指定步骤恢复"""
        state = self.load_state(report_name)
        if not state:
            return False

        # 获取步骤顺序
        step_order = ["parse", "github", "deploy", "cvss", "sqlmap", "generate"]

        if step not in step_order:
            return False

        step_idx = step_order.index(step)

        # 检查之前的步骤是否已完成
        for i in range(step_idx):
            prev_step = step_order[i]
            if state.steps[prev_step].status != "completed":
                return False

        return True
