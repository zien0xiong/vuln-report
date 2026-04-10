#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CVSSAgent - 漏洞评分Agent
使用大模型评估CVSS 3.1分数
"""

import json
from typing import Dict, Any

from agents.base_agent import BaseAgent
from core.state import TaskState
from core.llm_client import LLMClient


class CVSSAgent(BaseAgent):
    """CVSS评分Agent"""

    def __init__(self, llm_client: LLMClient = None):
        super().__init__("CVSSAgent", llm_client)

    def _execute(self, state: TaskState) -> Dict[str, Any]:
        """
        执行CVSS评分任务
        """
        # 加载ParseAgent的输出
        parsed_data = self._load_previous_output(state, "parse", "parsed.json")

        if not parsed_data:
            raise RuntimeError("找不到ParseAgent的输出")

        vuln_type = parsed_data.get("vulnerability_type", "")
        vuln_desc = parsed_data.get("vulnerability_principle", "")
        severity = parsed_data.get("severity", "")

        self.logger.info(f"评估CVSS: {vuln_type}")

        # 使用大模型评估
        cvss_result = self._evaluate_cvss(vuln_type, vuln_desc, severity)

        self.logger.info(f"CVSS评分: {cvss_result.get('base_score')} ({cvss_result.get('severity')})")

        # 保存结果
        output_path = self._get_output_path(state, "cvss_result.json")
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(cvss_result, f, ensure_ascii=False, indent=2)

        return {
            "output_path": str(output_path),
            "data": cvss_result
        }

    def _evaluate_cvss(self, vuln_type: str, vuln_desc: str, severity: str) -> Dict[str, Any]:
        """
        使用大模型评估CVSS分数
        """
        if not self.llm:
            # 如果没有LLM，使用简单映射
            return self._simple_cvss_mapping(vuln_type, severity)

        prompt = f"""根据以下漏洞信息，评估CVSS 3.1分数：

【漏洞类型】: {vuln_type}
【漏洞描述】: {vuln_desc}
【原始等级】: {severity}

请基于CVSS 3.1标准，评估以下维度：
- 攻击向量 (AV): Network/Adjacent/Local/Physical
- 攻击复杂度 (AC): Low/High
- 权限要求 (PR): None/Low/High
- 用户交互 (UI): None/Required
- 范围 (S): Unchanged/Changed
- 机密性影响 (C): None/Low/High
- 完整性影响 (I): None/Low/High
- 可用性影响 (A): None/Low/High

返回JSON格式：
{{
    "vector_string": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
    "base_score": 7.9,
    "severity": "High",
    "metrics": {{
        "attack_vector": "Network",
        "attack_complexity": "Low",
        "privileges_required": "Low",
        "user_interaction": "None",
        "scope": "Unchanged",
        "confidentiality": "High",
        "integrity": "High",
        "availability": "None"
    }},
    "assessment_reasoning": "评分理由..."
}}

注意：
1. SQL注入通常评分7.0-8.5（高危）
2. XSS通常评分4.0-6.5（中危）
3. 提供简要的评分理由
4. 只返回JSON，不要其他文本"""

        response = self.llm.complete(prompt=prompt, json_mode=True)

        if response["success"]:
            try:
                content = response["content"]
                if isinstance(content, str):
                    result = json.loads(content)
                else:
                    result = content

                # 确保必要字段
                if "base_score" not in result:
                    result["base_score"] = 7.0
                if "severity" not in result:
                    result["severity"] = "High"

                return result
            except Exception as e:
                self.logger.error(f"解析CVSS结果失败: {e}")

        # 降级方案
        return self._simple_cvss_mapping(vuln_type, severity)

    def _simple_cvss_mapping(self, vuln_type: str, severity: str) -> Dict[str, Any]:
        """
        简单的CVSS映射（降级方案）
        """
        vuln_lower = vuln_type.lower()

        # 基于漏洞类型映射
        if "sql" in vuln_lower or "注入" in vuln_type:
            score = 7.5
            severity = "High"
            vector = "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N"
        elif "xss" in vuln_lower or "脚本" in vuln_type:
            score = 5.4
            severity = "Medium"
            vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"
        elif "rce" in vuln_lower or "执行" in vuln_type:
            score = 8.8
            severity = "High"
            vector = "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"
        elif "file" in vuln_lower or "upload" in vuln_lower or "上传" in vuln_type:
            score = 7.2
            severity = "High"
            vector = "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H"
        else:
            # 基于原始等级
            severity_map = {
                "低危": (3.5, "Low"),
                "中危": (5.5, "Medium"),
                "高危": (7.5, "High"),
                "严重": (9.0, "Critical")
            }
            score, severity = severity_map.get(severity, (5.0, "Medium"))
            vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N"

        return {
            "vector_string": vector,
            "base_score": score,
            "severity": severity,
            "metrics": {
                "attack_vector": "Network",
                "attack_complexity": "Low",
                "privileges_required": "None" if score > 6 else "Low",
                "user_interaction": "None",
                "scope": "Unchanged",
                "confidentiality": "High" if score > 6 else "Low",
                "integrity": "High" if score > 6 else "Low",
                "availability": "None"
            },
            "assessment_reasoning": "基于漏洞类型的简单映射评估"
        }
