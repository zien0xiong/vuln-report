#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
GenerateAgent - 报告生成Agent
整合所有信息，生成最终CNVD报告（Word格式）
使用pywin32嵌入OLE对象
"""

import json
import shutil
from pathlib import Path
from typing import Dict, Any, List

from agents.base_agent import BaseAgent
from core.state import TaskState


class GenerateAgent(BaseAgent):
    """报告生成Agent"""

    def __init__(self, llm_client=None):
        super().__init__("GenerateAgent", llm_client)

    def _execute(self, state: TaskState) -> Dict[str, Any]:
        """
        执行报告生成任务
        """
        report_name = state.report_name

        # 加载所有前序Agent的输出
        parsed_data = self._load_previous_output(state, "parse", "parsed.json")
        github_result = self._load_previous_output(state, "github", "github_result.json")
        deployment_data = self._load_previous_output(state, "deploy", "deployment.json")
        cvss_result = self._load_previous_output(state, "cvss", "cvss_result.json")
        sqlmap_result = self._load_previous_output(state, "sqlmap", "sqlmap_result.json")

        self.logger.info(f"开始生成CNVD报告: {report_name}")

        # 准备数据
        data = self._prepare_report_data(
            parsed_data, github_result, deployment_data,
            cvss_result, sqlmap_result
        )

        # 输出文件路径
        output_path = Path(f"workspace/output/{report_name}.docx")
        output_path.parent.mkdir(parents=True, exist_ok=True)

        # 复制CNVD模板
        template_path = Path("templates/cnvd_template.docx")
        if template_path.exists():
            shutil.copy2(template_path, output_path)
            # 使用pywin32填充内容
            self._fill_word_document(output_path, data)
        else:
            self.logger.warning(f"模板不存在，使用基础报告回退生成: {template_path}")
            self._create_basic_report(output_path, data)

        self.logger.info(f"CNVD报告已生成: {output_path}")

        return {
            "output_path": str(output_path),
            "data": {"report_path": str(output_path)}
        }

    def _prepare_report_data(self, parsed_data: dict, github_result: dict,
                            deployment_data: dict, cvss_result: dict,
                            sqlmap_result: dict) -> Dict[str, Any]:
        """准备报告数据"""
        data = {
            # 产品介绍
            "product_description": parsed_data.get("product_description", ""),

            # 源码下载链接（新增）
            "source_download_url": github_result.get("download_url", "") if github_result else "",
            "repository_url": github_result.get("repository_url", "") if github_result else "",

            # 漏洞文件列表
            "vulnerable_files": [],

            # 漏洞评分（CVSS 3.1）
            "cvss_score": cvss_result.get("base_score", "N/A") if cvss_result else "N/A",
            "cvss_vector": cvss_result.get("vector_string", "") if cvss_result else "",
            "severity": cvss_result.get("severity", "") if cvss_result else "",

            # 漏洞原理
            "vulnerability_principle": parsed_data.get("vulnerability_principle", ""),

            # 漏洞URL
            "vulnerable_url": parsed_data.get("vulnerable_url", ""),

            # 复现流程
            "reproduction_steps": parsed_data.get("reproduction_steps", []),

            # sqlmap截图
            "sqlmap_screenshot": None,
            "sqlmap_executed": False,
            "sqlmap_failure_reason": "",
            "sqlmap_error": "",
        }

        # 添加漏洞文件列表（用于OLE嵌入）
        if deployment_data and "files_to_embed" in deployment_data:
            data["vulnerable_files"] = deployment_data["files_to_embed"]

        # 添加sqlmap截图路径
        if sqlmap_result and sqlmap_result.get("screenshot_path"):
            data["sqlmap_screenshot"] = sqlmap_result["screenshot_path"]
        if sqlmap_result:
            data["sqlmap_executed"] = bool(sqlmap_result.get("executed", False))
            data["sqlmap_failure_reason"] = str(sqlmap_result.get("failure_reason", "") or "")
            data["sqlmap_error"] = str(sqlmap_result.get("error", "") or "")

        return data

    def _create_basic_report(self, output_path: Path, data: Dict[str, Any]) -> None:
        """当模板缺失时，按参考CNVD样式生成结构化报告，避免空白文档。"""
        from docx import Document

        doc = Document()

        # 1) 产品介绍
        doc.add_heading("产品介绍", level=1)
        doc.add_paragraph(data.get("product_description", "") or "N/A")
        source_url = data.get("source_download_url", "") or ""
        if source_url:
            doc.add_paragraph(f"源码下载链接：{source_url}")
        else:
            repo_url = data.get("repository_url", "") or ""
            doc.add_paragraph(f"源码下载链接：{repo_url or 'N/A'}")

        # 2) 存在漏洞的代码文件
        doc.add_heading("存在漏洞的代码文件", level=1)
        vulnerable_files = data.get("vulnerable_files", []) or []
        if vulnerable_files:
            for item in vulnerable_files:
                if isinstance(item, dict):
                    preferred = item.get("original_path") or item.get("display_name") or item.get("source_path")
                    doc.add_paragraph(str(preferred or "N/A"))
                else:
                    doc.add_paragraph(str(item))
        else:
            doc.add_paragraph("N/A")

        # 3) 漏洞评分
        doc.add_heading("漏洞评分", level=1)
        doc.add_paragraph(f"CVSS3.1：{data.get('cvss_score', 'N/A')}")

        # 4) 漏洞原理
        doc.add_heading("漏洞原理", level=1)
        doc.add_paragraph(data.get("vulnerability_principle", "") or "N/A")

        # 5) 漏洞URL
        doc.add_heading("漏洞URL", level=1)
        doc.add_paragraph(data.get("vulnerable_url", "") or "N/A")

        # 6) 复现流程
        doc.add_heading("复现流程", level=1)
        steps = data.get("reproduction_steps", []) or []
        if steps:
            for step in steps:
                doc.add_paragraph(str(step))
        else:
            doc.add_paragraph("N/A")
        if not data.get("sqlmap_executed", False):
            fail_reason = data.get("sqlmap_failure_reason", "") or "sqlmap未执行成功"
            fail_error = data.get("sqlmap_error", "")
            doc.add_paragraph(f"自动复现状态：失败（{fail_reason}）")
            if fail_error:
                doc.add_paragraph(f"失败详情：{fail_error}")

        # 7) sqlmap 截图（如果有）
        sqlmap_screenshot = data.get("sqlmap_screenshot")
        if sqlmap_screenshot:
            try:
                doc.add_heading("sqlmap截图", level=1)
                doc.add_picture(sqlmap_screenshot)
            except Exception:
                doc.add_heading("sqlmap截图", level=1)
                doc.add_paragraph(sqlmap_screenshot)

        doc.save(output_path)

    def _fill_word_document(self, doc_path: Path, data: Dict[str, Any]):
        """
        使用pywin32填充Word文档
        """
        try:
            import win32com.client
            from win32com.client import constants

            # 启动Word
            word = win32com.client.Dispatch("Word.Application")
            word.Visible = False

            try:
                # 打开文档
                doc = word.Documents.Open(str(doc_path.absolute()))

                # 1. 填充产品介绍（添加源码链接）
                self._find_and_replace(doc, "产品介绍", data.get("product_description", ""))
                if data.get("source_download_url"):
                    self._append_text(doc, "产品介绍", f"\n源码下载链接：{data['source_download_url']}")

                # 2. 填充漏洞评分
                self._find_and_replace(doc, "漏洞评分", f"CVSS 3.1：{data.get('cvss_score', 'N/A')}")

                # 3. 填充漏洞原理
                self._find_and_replace(doc, "漏洞原理", data.get("vulnerability_principle", ""))

                # 4. 填充漏洞URL
                self._find_and_replace(doc, "漏洞URL", data.get("vulnerable_url", ""))

                # 5. 填充复现流程
                steps = data.get("reproduction_steps", [])
                if steps:
                    steps_text = "\n".join([f"{i+1}. {step}" for i, step in enumerate(steps)])
                    if not data.get("sqlmap_executed", False):
                        fail_reason = data.get("sqlmap_failure_reason", "") or "sqlmap未执行成功"
                        fail_error = data.get("sqlmap_error", "")
                        extra = f"\n自动复现状态：失败（{fail_reason}）"
                        if fail_error:
                            extra += f"\n失败详情：{fail_error}"
                        steps_text += extra
                    self._find_and_replace(doc, "复现流程", steps_text)

                # 6. 嵌入漏洞代码文件（OLE对象）
                self._embed_vulnerable_files(doc, data.get("vulnerable_files", []))

                # 7. 嵌入sqlmap截图
                if data.get("sqlmap_screenshot"):
                    self._embed_screenshot(doc, data["sqlmap_screenshot"])

                # 保存
                doc.Save()
                doc.Close()

            finally:
                word.Quit()

        except ImportError:
            self.logger.error("pywin32未安装，无法操作Word文档")
            raise
        except Exception as e:
            self.logger.error(f"填充Word文档失败: {e}")
            raise

    def _find_and_replace(self, doc, search_text: str, replace_text: str):
        """查找并替换文本"""
        try:
            # 使用Word的查找功能
            selection = doc.Content
            selection.Find.ClearFormatting()
            selection.Find.Replacement.ClearFormatting()

            selection.Find.Text = search_text
            selection.Find.Replacement.Text = replace_text
            selection.Find.Execute(
                Replace=2  # wdReplaceAll = 2
            )
        except Exception as e:
            self.logger.warning(f"查找替换失败 '{search_text}': {e}")

    def _append_text(self, doc, search_text: str, append_text: str):
        """在找到的文本后追加内容"""
        try:
            selection = doc.Content
            selection.Find.Text = search_text

            if selection.Find.Execute():
                selection.Collapse(Direction=0)  # Collapse to end
                selection.InsertAfter(append_text)
        except Exception as e:
            self.logger.warning(f"追加文本失败 '{search_text}': {e}")

    def _embed_vulnerable_files(self, doc, files_to_embed: List[Dict[str, str]]):
        """嵌入漏洞代码文件（OLE对象）"""
        if not files_to_embed:
            return

        try:
            # 查找"存在漏洞的代码文件"位置
            selection = doc.Content
            selection.Find.Text = "存在漏洞的代码文件"

            if selection.Find.Execute():
                # 移动到标题后
                selection.Collapse(Direction=0)
                selection.InsertAfter("\n\n")

                # 嵌入每个文件
                for file_info in files_to_embed:
                    file_path = file_info.get("source_path", "")
                    display_name = file_info.get("display_name", "")

                    if Path(file_path).exists():
                        # 插入OLE对象
                        inline_shape = selection.InlineShapes.AddOLEObject(
                            ClassType=None,
                            FileName=file_path,
                            LinkToFile=False,
                            DisplayAsIcon=True,
                            IconFileName=None,
                            IconIndex=0,
                            IconLabel=display_name
                        )

                        # 移动到对象后，添加换行
                        selection.Collapse(Direction=0)
                        selection.InsertAfter("\n")

                        self.logger.info(f"已嵌入文件: {display_name}")
                    else:
                        self.logger.warning(f"文件不存在，无法嵌入: {file_path}")

        except Exception as e:
            self.logger.error(f"嵌入文件失败: {e}")

    def _embed_screenshot(self, doc, screenshot_path: str):
        """嵌入sqlmap截图"""
        try:
            selection = doc.Content
            selection.Find.Text = "sqlmap截图"

            if selection.Find.Execute():
                selection.Collapse(Direction=0)
                selection.InsertParagraphAfter()

                # 插入图片
                doc.InlineShapes.AddPicture(
                    FileName=screenshot_path,
                    LinkToFile=False,
                    SaveWithDocument=True
                )

                self.logger.info(f"已嵌入截图: {screenshot_path}")

        except Exception as e:
            self.logger.error(f"嵌入截图失败: {e}")
