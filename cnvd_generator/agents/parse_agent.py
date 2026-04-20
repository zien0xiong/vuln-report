#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ParseAgent - 解析可信代码库报告
提取关键信息：产品名称、漏洞描述、复现步骤等
"""

import json
import re
import tempfile
import time
import zipfile
from pathlib import Path
from typing import Dict, Any, List
from urllib.parse import urlparse

from agents.base_agent import BaseAgent
from core.state import TaskState
from core.llm_client import LLMClient
from tools.read_word import extract_docx


class ParseAgent(BaseAgent):
    """解析Agent"""

    def __init__(self, llm_client: LLMClient = None):
        super().__init__("ParseAgent", llm_client)

    def _execute(self, state: TaskState) -> Dict[str, Any]:
        """
        执行解析任务

        1. 调用 tools.read_word 提取 Word 内容
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
        parsed_data = self._enrich_github_links_from_images(input_file, parsed_data)
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
        使用 tools.read_word 提取 Word 文本。

        Args:
            docx_path: Word 文件路径

        Returns:
            提取出的纯文本
        """
        import shutil

        source_path = Path(docx_path)
        if not source_path.exists():
            raise FileNotFoundError(f"Word文件不存在: {source_path}")

        self.logger.info("调用 tools.read_word.extract_docx 提取 Word 内容")

        tmp_root = Path("workspace") / "tmp" / "parse_readword"
        tmp_root.mkdir(parents=True, exist_ok=True)
        run_dir = tmp_root / f"run_{int(time.time() * 1000)}"
        output_dir = run_dir / "extracted"
        run_dir.mkdir(parents=True, exist_ok=True)

        try:
            try:
                extract_docx(docx_path=source_path, output_dir=output_dir)
            except Exception as error:
                self.logger.error(f"tools.read_word 提取失败: {error}")
                raise RuntimeError(f"无法提取Word文本: {error}")

            text_file = output_dir / "extracted_text.txt"
            if text_file.exists():
                for enc in ("utf-8", "gbk"):
                    try:
                        with open(text_file, "r", encoding=enc, errors="replace") as f:
                            return f.read()
                    except Exception:
                        continue

            document_xml = output_dir / "xml" / "document.xml"
            if document_xml.exists():
                return self._parse_document_xml(document_xml)

            raise RuntimeError("无法从Word中提取文本内容")
        finally:
            try:
                shutil.rmtree(run_dir, ignore_errors=True)
            except Exception:
                pass

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
    "severity": "漏洞等级（低危/中危/高危/严重）",
    "auth": {{
        "login_path": "登录路径（如 /admin/auth/login）",
        "username": "登录用户名",
        "password": "登录密码",
        "username_field": "用户名字段名（如 username）",
        "password_field": "密码字段名（如 password）",
        "csrf_field": "csrf字段名（如 _token）"
    }}
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
            data = self._normalize_auth_fields(data, text_content)

            # 验证必要字段
            required_fields = ["product_name", "vulnerability_type"]
            for field in required_fields:
                if field not in data or data[field] is None:
                    self.logger.warning(f"必要字段缺失: {field}")

            return data

        except json.JSONDecodeError as e:
            self.logger.error(f"JSON解析失败: {e}")
            raise RuntimeError(f"无法解析LLM响应为JSON: {response['content'][:200]}")

    def _normalize_auth_fields(self, data: Dict[str, Any], text_content: str) -> Dict[str, Any]:
        auth = data.get("auth", {})
        if not isinstance(auth, dict):
            auth = {}

        key_mapping = {
            "auth_login_path": "login_path",
            "login_path": "login_path",
            "auth_username": "username",
            "username": "username",
            "auth_password": "password",
            "password": "password",
            "auth_username_field": "username_field",
            "username_field": "username_field",
            "auth_password_field": "password_field",
            "password_field": "password_field",
            "auth_csrf_field": "csrf_field",
            "csrf_field": "csrf_field",
        }

        for src_key, target_key in key_mapping.items():
            value = data.get(src_key)
            if value is None:
                continue
            text = str(value).strip()
            if text and not str(auth.get(target_key, "")).strip():
                auth[target_key] = text

        regex_auth = self._extract_auth_from_text(text_content)
        for key, value in regex_auth.items():
            if value and not str(auth.get(key, "")).strip():
                auth[key] = value

        if auth:
            data["auth"] = auth
        return data

    def _extract_auth_from_text(self, text: str) -> Dict[str, str]:
        raw = str(text or "")
        result: Dict[str, str] = {}

        login_url_match = re.search(r"https?://[^\s\"'<>]*?/[^ \n\"'<>]*login[^ \n\"'<>]*", raw, flags=re.I)
        if login_url_match:
            try:
                from urllib.parse import urlparse

                parsed = urlparse(login_url_match.group(0).strip())
                if parsed.path:
                    result["login_path"] = parsed.path
            except Exception:
                pass

        if "login_path" not in result:
            login_path_match = re.search(r"(/[^ \n\"'<>]*login[^ \n\"'<>]*)", raw, flags=re.I)
            if login_path_match:
                result["login_path"] = login_path_match.group(1).strip()

        username_match = re.search(
            r"(?:^|[\r\n])\s*(?:用户名|账号|username|user)\s*[：:]\s*([A-Za-z0-9_.@-]{1,64})",
            raw,
            flags=re.I,
        )
        if username_match:
            result["username"] = username_match.group(1).strip()

        password_match = re.search(
            r"(?:^|[\r\n])\s*(?:密码|password|pass)\s*[：:]\s*([^\s，。,；;]{1,128})",
            raw,
            flags=re.I,
        )
        if password_match:
            result["password"] = password_match.group(1).strip()

        field_patterns = {
            "username_field": r"(?:^|[\r\n])\s*(?:用户名字段|账号字段|username[_\-\s]*field)\s*[：:]\s*([A-Za-z0-9_.\[\]-]{1,64})",
            "password_field": r"(?:^|[\r\n])\s*(?:密码字段|password[_\-\s]*field)\s*[：:]\s*([A-Za-z0-9_.\[\]-]{1,64})",
            "csrf_field": r"(?:^|[\r\n])\s*(?:csrf字段|token字段|csrf[_\-\s]*field)\s*[：:]\s*([A-Za-z0-9_.\[\]-]{1,64})",
        }
        for key, pattern in field_patterns.items():
            match = re.search(pattern, raw, flags=re.I)
            if match:
                result[key] = match.group(1).strip()

        return result

    def _enrich_github_links_from_images(self, docx_path: str, parsed_data: Dict[str, Any]) -> Dict[str, Any]:
        """通过截图 OCR 补充 GitHub 链接，失败时不影响主流程。"""
        if not self.llm:
            return parsed_data

        all_texts: List[str] = []
        all_urls: List[str] = []
        prompt = (
            "请识别图片中的文字，并尽量完整提取 GitHub 链接。"
            "若出现源码下载链接（zip/tar.gz），请原样输出。仅输出识别文本。"
        )

        try:
            with tempfile.TemporaryDirectory() as tmpdir:
                image_paths = self._extract_docx_images(Path(docx_path), Path(tmpdir), max_images=12)
                if not image_paths:
                    return parsed_data

                self.logger.info(f"开始图片OCR补充解析，图片数: {len(image_paths)}")
                for image_path in image_paths:
                    response = self.llm.vision_complete(
                        image_path=str(image_path),
                        prompt=prompt,
                        model=None,
                        max_tokens=600,
                    )
                    if not response.get("success"):
                        self.logger.warning(f"图片OCR失败({image_path.name}): {response.get('error')}")
                        continue
                    content = str(response.get("content") or "").strip()
                    if not content:
                        continue
                    all_texts.append(content)
                    all_urls.extend(self._extract_github_urls(content))
        except Exception as error:
            self.logger.warning(f"图片OCR补充解析异常: {error}")
            return parsed_data

        urls = self._dedupe_keep_order(all_urls)
        if all_texts:
            parsed_data["image_ocr_text"] = "\n\n".join(all_texts)
        if urls:
            parsed_data["ocr_github_urls"] = urls

        selected_repo = self._choose_best_repo_url(urls, parsed_data)
        if not str(parsed_data.get("repository_url", "")).strip() and selected_repo:
            parsed_data["repository_url"] = selected_repo

        if not str(parsed_data.get("source_download_url", "")).strip():
            preferred_repo = str(parsed_data.get("repository_url", "") or "").strip() or selected_repo
            archive_candidates = [u for u in urls if self._looks_like_archive_url(u)]
            if preferred_repo:
                matched = [u for u in archive_candidates if self._repo_url_from_github_url(u) == preferred_repo]
                if matched:
                    archive_candidates = matched
            if archive_candidates:
                parsed_data["source_download_url"] = archive_candidates[0]

        if urls:
            self.logger.info(f"图片OCR提取到 GitHub 链接 {len(urls)} 条")
        return parsed_data

    def _choose_best_repo_url(self, urls: List[str], parsed_data: Dict[str, Any]) -> str:
        repo_candidates = self._dedupe_keep_order([self._repo_url_from_github_url(u) for u in urls if u])
        repo_candidates = [u for u in repo_candidates if u]
        if not repo_candidates:
            return ""

        product_name = str(parsed_data.get("product_name", "") or "").lower()
        product_tokens = re.findall(r"[a-z0-9]+", product_name)
        product_tokens = [t for t in product_tokens if len(t) >= 3]

        best_repo = repo_candidates[0]
        best_score = -10
        for repo in repo_candidates:
            low = repo.lower()
            score = 0
            for token in product_tokens:
                if token in low:
                    score += 2
            if "archive" in low:
                score -= 1
            if "github.com/" in low:
                score += 1
            if score > best_score:
                best_score = score
                best_repo = repo
        return best_repo

    def _extract_docx_images(self, docx_path: Path, output_dir: Path, max_images: int = 6) -> List[Path]:
        if not docx_path.exists():
            return []
        output_dir.mkdir(parents=True, exist_ok=True)
        valid_exts = (".png", ".jpg", ".jpeg", ".webp", ".bmp")
        paths: List[Path] = []

        with zipfile.ZipFile(docx_path, "r") as zf:
            infos = [
                info
                for info in zf.infolist()
                if info.filename.startswith("word/media/")
                and info.filename.lower().endswith(valid_exts)
            ]
            infos.sort(key=lambda i: self._natural_sort_key(Path(i.filename).name))
            for info in infos[:max_images]:
                target = output_dir / Path(info.filename).name
                target.write_bytes(zf.read(info.filename))
                paths.append(target)
        return paths

    def _natural_sort_key(self, text: str) -> List[Any]:
        parts = re.split(r"(\d+)", str(text or ""))
        key: List[Any] = []
        for part in parts:
            if part.isdigit():
                key.append(int(part))
            else:
                key.append(part.lower())
        return key

    def _extract_github_urls(self, text: str) -> List[str]:
        pattern = r"https?://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(?:/[^\s<>'\"，。；;\)\]]*)?"
        urls = re.findall(pattern, str(text or ""), flags=re.I)
        result: List[str] = []
        for url in urls:
            value = str(url).strip().rstrip(".,);]}>")
            if value:
                result.append(value)
        return result

    def _repo_url_from_github_url(self, url: str) -> str:
        try:
            parsed = urlparse(str(url).strip())
            if parsed.netloc.lower() != "github.com":
                return ""
            parts = [p for p in parsed.path.split("/") if p]
            if len(parts) < 2:
                return ""
            return f"https://github.com/{parts[0]}/{parts[1]}"
        except Exception:
            return ""

    def _looks_like_archive_url(self, url: str) -> bool:
        low = str(url or "").lower()
        return (
            "/archive/" in low
            or "/zipball/" in low
            or "/tarball/" in low
            or low.endswith(".zip")
            or low.endswith(".tar.gz")
        )

    def _dedupe_keep_order(self, items: List[str]) -> List[str]:
        seen = set()
        result: List[str] = []
        for item in items:
            text = str(item or "").strip()
            if not text:
                continue
            key = text.lower()
            if key in seen:
                continue
            seen.add(key)
            result.append(text)
        return result
