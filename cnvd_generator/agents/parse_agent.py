#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ParseAgent - 解析可信代码库报告
提取关键信息：产品名称、漏洞描述、复现步骤等
"""

import json
import re
import subprocess
from pathlib import Path
from typing import Dict, Any

from agents.base_agent import BaseAgent
from core.state import TaskState
from core.llm_client import LLMClient


class ParseAgent(BaseAgent):
    """解析Agent"""

    def __init__(self, llm_client: LLMClient = None):
        super().__init__("ParseAgent", llm_client)

    def _execute(self, state: TaskState) -> Dict[str, Any]:
        """
        执行解析任务

        1. 调用read_word.py提取Word内容
        2. 使用大模型提取结构化信息
        3. 保存解析结果
        """
        input_file = state.input_file
        self.logger.info(f"开始解析文件: {input_file}")

        # Step 1: 提取Word文本内容
        text_content = self._extract_text_from_word(input_file)
        self.logger.info(f"成功提取文本，共{len(text_content)}字符")

        # Step 2: 使用大模型提取结构化信息
        parsed_data = self._extract_structure(text_content)
        self.logger.info(f"结构化提取完成: {parsed_data.get('product_name', 'Unknown')}")

        # Step 3: 保存结果
        output_path = self._get_output_path(state, "parsed.json")
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(parsed_data, f, ensure_ascii=False, indent=2)

        self.logger.info(f"解析结果已保存: {output_path}")

        return {
            "output_path": str(output_path),
            "data": parsed_data
        }

    def _extract_text_from_word(self, docx_path: str) -> str:
        """
        调用read_word.py提取Word文档文本

        Args:
            docx_path: Word文档路径

        Returns:
            提取的文本内容
        """
        import tempfile
        import shutil
        from pathlib import Path

        docx_path = Path(docx_path)

        if not docx_path.exists():
            raise FileNotFoundError(f"Word文件不存在: {docx_path}")

        # 查找read_word.py的路径
        script_dir = Path(__file__).parent.parent.parent  # cnvd_generator的父目录
        read_word_script = script_dir / "read_word.py"

        if not read_word_script.exists():
            # 尝试相对路径
            read_word_script = Path("read_word.py")

        if not read_word_script.exists():
            raise FileNotFoundError(f"找不到read_word.py脚本")

        self.logger.info(f"使用read_word.py: {read_word_script}")

        # 创建临时输出目录
        with tempfile.TemporaryDirectory() as tmpdir:
            output_dir = Path(tmpdir) / "extracted"

            # 调用read_word.py
            try:
                import sys
                result = subprocess.run(
                    [sys.executable, str(read_word_script), str(docx_path), str(output_dir)],
                    capture_output=True,
                    text=True,
                    encoding='utf-8',
                    errors='replace',
                    timeout=60
                )

                if result.returncode != 0:
                    stderr_msg = result.stderr if result.stderr else "未知错误"
                    stdout_msg = result.stdout if result.stdout else ""
                    self.logger.error(f"read_word.py执行失败: {stderr_msg}")
                    self.logger.error(f"stdout: {stdout_msg}")
                    raise RuntimeError(f"提取Word内容失败: {stderr_msg}")

            except subprocess.TimeoutExpired:
                raise RuntimeError("提取Word内容超时")
            except FileNotFoundError as e:
                raise RuntimeError(f"找不到python命令或read_word.py: {e}")

            # 读取提取的文本
            text_file = output_dir / "extracted_text.txt"
            if text_file.exists():
                for enc in ("utf-8", "gbk"):
                    try:
                        with open(text_file, 'r', encoding=enc, errors='replace') as f:
                            return f.read()
                    except Exception:
                        continue

            # 如果没有文本文件，尝试从document.xml解析
            document_xml = output_dir / "xml" / "document.xml"
            if document_xml.exists():
                return self._parse_document_xml(document_xml)

            raise RuntimeError("无法提取Word文档文本内容")

    def _parse_document_xml(self, xml_path: Path) -> str:
        """从document.xml解析文本"""
        from xml.etree import ElementTree as ET

        ns = {'w': 'http://schemas.openxmlformats.org/wordprocessingml/2006/main'}

        tree = ET.parse(xml_path)
        root = tree.getroot()

        texts = []
        for paragraph in root.findall('.//w:p', ns):
            para_text = []
            for node in paragraph.findall('.//w:t', ns):
                if node.text:
                    para_text.append(node.text)
            if para_text:
                texts.append(''.join(para_text))

        return '\n'.join(texts)

    def _extract_structure(self, text_content: str) -> Dict[str, Any]:
        """
        使用大模型提取结构化信息

        Args:
            text_content: Word文档的文本内容

        Returns:
            结构化数据字典
        """
        if not self.llm:
            raise ValueError("LLM client is required for structure extraction")

        # 截取前8000字符（避免超出token限制）
        text_preview = text_content[:8000]

        prompt = f"""分析以下可信代码库报告，提取关键信息：

【报告内容】
{text_preview}

请提取以下信息并返回JSON格式：
{{
    "product_name": "产品名称",
    "product_description": "产品介绍",
    "vulnerability_type": "漏洞类型（如SQL注入、XSS等）",
    "vulnerable_files": ["存在漏洞的文件路径列表"],
    "vulnerability_principle": "漏洞原理说明",
    "vulnerable_url": "漏洞URL",
    "reproduction_steps": ["复现步骤列表"],
    "sqlmap_command": "sqlmap命令（如果有）",
    "severity": "漏洞等级（低危/中危/高危/严重）"
}}

注意：
1. 如果某项信息在报告中不存在，使用null
2. vulnerable_files应该是相对路径列表
3. reproduction_steps按步骤顺序列出
4. 只返回JSON，不要包含其他文本"""

        self.logger.log_llm_interaction(
            prompt=prompt[:500] + "...",
            response="等待响应...",
            tokens={}
        )

        # 调用LLM
        response = self.llm.complete(
            prompt=prompt,
            json_mode=True
        )

        if not response["success"]:
            raise RuntimeError(f"LLM提取失败: {response.get('error')}")

        # 解析JSON响应
        try:
            content = response["content"]
            if isinstance(content, str):
                data = json.loads(content)
            else:
                data = content

            # 添加原始文本
            data["raw_text"] = text_content

            # 验证必要字段
            required_fields = ["product_name", "vulnerability_type"]
            for field in required_fields:
                if field not in data or data[field] is None:
                    self.logger.warning(f"必要字段缺失: {field}")

            return data

        except json.JSONDecodeError as e:
            self.logger.error(f"JSON解析失败: {e}")
            raise RuntimeError(f"无法解析LLM响应为JSON: {response['content'][:200]}")
