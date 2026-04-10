#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
GitHubSearchAgent - 搜索GitHub源码下载链接
根据产品信息找到对应的GitHub仓库和版本
"""

import json
import re
import requests
from pathlib import Path
from typing import Dict, Any, Optional, List
from urllib.parse import quote

from agents.base_agent import BaseAgent
from core.state import TaskState
from core.llm_client import LLMClient


class GitHubSearchAgent(BaseAgent):
    """GitHub搜索Agent"""

    def __init__(self, llm_client: LLMClient = None):
        super().__init__("GitHubSearchAgent", llm_client)
        self.github_api = "https://api.github.com"

    def _execute(self, state: TaskState) -> Dict[str, Any]:
        """
        执行GitHub搜索任务

        1. 从ParseAgent输出获取产品信息
        2. 搜索GitHub仓库
        3. 使用大模型判断最佳匹配
        4. 获取下载链接
        """
        # 加载ParseAgent的输出
        parsed_data = self._load_previous_output(state, "parse", "parsed.json")
        if not parsed_data:
            raise RuntimeError("找不到ParseAgent的输出，请先执行ParseAgent")

        product_name = parsed_data.get("product_name", "")
        product_description = parsed_data.get("product_description", "")

        self.logger.info(f"搜索GitHub仓库: {product_name}")

        # Step 1: 构建搜索查询
        search_queries = self._build_search_queries(product_name, product_description)

        # Step 2: 搜索GitHub
        search_results = []
        for query in search_queries:
            results = self._search_github(query)
            search_results.extend(results)
            if len(search_results) >= 5:
                break

        for index, repo in enumerate(search_results):
            if index >= 8:
                break
            runnable_meta = self._assess_repo_runnable(repo)
            repo.update(runnable_meta)

        if not search_results:
            self.logger.warning("GitHub搜索未找到结果")
            return {
                "output_path": None,
                "data": {
                    "repository_url": None,
                    "download_url": None,
                    "error": "未找到匹配的GitHub仓库"
                }
            }

        # Step 3: 使用大模型选择最佳匹配
        best_match = self._select_best_match(
            product_name,
            product_description,
            search_results
        )

        # Step 4: 获取下载链接
        if best_match:
            download_info = self._get_download_url(best_match)
            self.logger.info(f"找到最佳匹配: {download_info.get('repository_url')}")
        else:
            download_info = {
                "repository_url": None,
                "download_url": None,
                "error": "无法确定最佳匹配"
            }

        # Step 5: 保存结果
        output_path = self._get_output_path(state, "github_result.json")
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(download_info, f, ensure_ascii=False, indent=2)

        return {
            "output_path": str(output_path),
            "data": download_info
        }

    def _build_search_queries(self, product_name: str, description: str) -> List[str]:
        """构建GitHub搜索查询"""
        queries = []

        # 清理产品名称
        clean_name = product_name.strip()

        # 基本查询
        queries.append(clean_name)

        # 添加关键词
        if description:
            # 从描述中提取关键词
            keywords = self._extract_keywords(description)
            if keywords:
                queries.append(f"{clean_name} {keywords}")

        # PHP项目常见后缀
        if "php" in description.lower() or "laravel" in description.lower():
            queries.append(f"{clean_name} php")

        return queries[:3]  # 最多3个查询

    def _extract_keywords(self, description: str) -> str:
        """从描述中提取关键词"""
        # 提取技术栈关键词
        tech_patterns = [
            r"(laravel|django|flask|spring|express|react|vue|angular)",
            r"(php|python|java|nodejs|ruby|go)",
            r"(admin|cms|framework|dashboard)"
        ]

        keywords = set()
        for pattern in tech_patterns:
            matches = re.findall(pattern, description, re.IGNORECASE)
            keywords.update(matches)

        return " ".join(keywords)

    def _search_github(self, query: str) -> List[Dict[str, Any]]:
        """
        使用GitHub API搜索仓库

        Args:
            query: 搜索关键词

        Returns:
            搜索结果列表
        """
        # 使用GitHub搜索API
        search_url = f"{self.github_api}/search/repositories"

        headers = {
            "Accept": "application/vnd.github.v3+json"
        }

        # 添加User-Agent避免被限制
        headers["User-Agent"] = "CNVD-Report-Generator"

        params = {
            "q": query,
            "sort": "stars",
            "order": "desc",
            "per_page": 10
        }

        try:
            response = requests.get(
                search_url,
                headers=headers,
                params=params,
                timeout=30
            )

            if response.status_code == 200:
                data = response.json()
                items = data.get("items", [])

                results = []
                for item in items:
                    results.append({
                        "full_name": item.get("full_name"),
                        "html_url": item.get("html_url"),
                        "description": item.get("description", ""),
                        "stars": item.get("stargazers_count", 0),
                        "language": item.get("language", ""),
                        "topics": item.get("topics", []),
                        "default_branch": item.get("default_branch", "main")
                    })

                self.logger.info(f"GitHub搜索 '{query}' 找到 {len(results)} 个结果")
                return results

            elif response.status_code == 403:
                self.logger.warning("GitHub API rate limit exceeded")
                return []
            else:
                self.logger.error(f"GitHub API错误: {response.status_code}")
                return []

        except requests.RequestException as e:
            self.logger.error(f"GitHub搜索请求失败: {e}")
            return []

    def _select_best_match(self, product_name: str, description: str,
                           search_results: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        """
        使用大模型选择最佳匹配的仓库

        Args:
            product_name: 产品名称
            description: 产品描述
            search_results: 搜索结果列表

        Returns:
            最佳匹配的仓库信息
        """
        if not self.llm or not search_results:
            # 如果没有LLM，优先可运行仓库，再看stars
            return max(
                search_results,
                key=lambda x: (x.get("runnable_score", 0), x.get("stars", 0)),
            )

        # 构建候选列表
        candidates_text = "\n\n".join([
            f"候选{i+1}:\n"
            f"  名称: {r['full_name']}\n"
            f"  描述: {r.get('description', 'N/A')}\n"
            f"  语言: {r.get('language', 'N/A')}\n"
            f"  Stars: {r.get('stars', 0)}\n"
            f"  可运行评分: {r.get('runnable_score', 0)}\n"
            f"  运行入口: {r.get('runtime_signals', [])}\n"
            f"  链接: {r['html_url']}"
            for i, r in enumerate(search_results[:5])
        ])

        prompt = f"""根据以下产品信息，从候选GitHub仓库中选择最佳匹配：

【产品信息】
名称: {product_name}
描述: {description[:500]}

【候选仓库】
{candidates_text}

请分析哪个仓库最匹配该产品，并返回JSON格式：
{{
    "selected_index": 1,
    "confidence": 0.95,
    "reason": "选择理由",
    "version_tag": "推测的版本标签（如v1.0.0）"
}}

注意：
1. selected_index是候选编号（1-5）
2. confidence是置信度（0-1）
3. 如果都不匹配，selected_index设为0
4. 同等匹配下，优先选择“可直接运行并可启动服务”的仓库（例如存在 artisan/manage.py/package start）
5. 只返回JSON，不要其他文本"""

        response = self.llm.complete(prompt=prompt, json_mode=True)

        if not response["success"]:
            self.logger.warning("LLM选择失败，使用默认选择")
            return search_results[0] if search_results else None

        try:
            result = json.loads(response["content"]) if isinstance(response["content"], str) else response["content"]
            selected_index = result.get("selected_index", 1) - 1  # 转换为0-based索引

            if 0 <= selected_index < len(search_results):
                selected = search_results[selected_index]
                selected["confidence"] = result.get("confidence", 0.8)
                selected["reason"] = result.get("reason", "")
                selected["version_tag"] = result.get("version_tag", "")
                return selected

        except Exception as e:
            self.logger.error(f"解析LLM选择结果失败: {e}")

        # 默认选择第一个
        return search_results[0] if search_results else None

    def _get_download_url(self, repo_info: Dict[str, Any]) -> Dict[str, Any]:
        """
        获取仓库的下载链接

        Args:
            repo_info: 仓库信息

        Returns:
            下载信息
        """
        import re

        repo_url = repo_info.get("html_url", "")
        default_branch = repo_info.get("default_branch", "main")

        # 构造ZIP下载链接
        # 优先使用推测的版本标签
        version_tag = repo_info.get("version_tag", "")

        # 验证版本号格式（必须包含数字，不能是纯中文）
        def is_valid_version(tag: str) -> bool:
            if not tag:
                return False
            # 检查是否包含中文字符
            if re.search(r'[\u4e00-\u9fff]', tag):
                return False
            # 检查是否包含版本号数字
            if not re.search(r'\d', tag):
                return False
            return True

        if version_tag and not version_tag.startswith("v"):
            version_tag = f"v{version_tag}"

        # 如果版本号无效，使用默认分支
        if not is_valid_version(version_tag):
            self.logger.warning(f"版本号无效 '{version_tag}'，使用默认分支: {default_branch}")
            version_tag = ""

        if version_tag:
            download_url = f"{repo_url}/archive/refs/tags/{version_tag}.zip"
        else:
            # 使用默认分支
            download_url = f"{repo_url}/archive/refs/heads/{default_branch}.zip"

        return {
            "repository_url": repo_url,
            "download_url": download_url,
            "version": version_tag or default_branch,
            "confidence": repo_info.get("confidence", 0.8),
            "runnable_score": repo_info.get("runnable_score", 0),
            "runtime_signals": repo_info.get("runtime_signals", []),
            "repository_info": {
                "full_name": repo_info.get("full_name"),
                "description": repo_info.get("description"),
                "stars": repo_info.get("stars"),
                "language": repo_info.get("language"),
                "default_branch": default_branch,
            }
        }

    def _assess_repo_runnable(self, repo_info: Dict[str, Any]) -> Dict[str, Any]:
        """粗粒度判断仓库是否更像可运行应用（而不是纯库）。"""
        full_name = repo_info.get("full_name")
        default_branch = repo_info.get("default_branch", "main")
        if not full_name:
            return {"runnable_score": 0, "runtime_signals": []}

        url = f"{self.github_api}/repos/{full_name}/contents"
        headers = {"Accept": "application/vnd.github.v3+json", "User-Agent": "CNVD-Report-Generator"}
        params = {"ref": default_branch}

        try:
            response = requests.get(url, headers=headers, params=params, timeout=20)
            if response.status_code != 200:
                return {"runnable_score": 0, "runtime_signals": []}

            items = response.json()
            if not isinstance(items, list):
                return {"runnable_score": 0, "runtime_signals": []}

            names = {str(item.get("name", "")).lower() for item in items}
            signals: List[str] = []

            if "artisan" in names:
                signals.append("artisan")
            if "manage.py" in names:
                signals.append("manage.py")
            if "docker-compose.yml" in names or "docker-compose.yaml" in names:
                signals.append("docker-compose")
            if "package.json" in names:
                signals.append("package.json")
            if "requirements.txt" in names:
                signals.append("requirements.txt")

            score = len(signals)
            if "artisan" in signals:
                score += 2
            if "manage.py" in signals:
                score += 2
            return {"runnable_score": score, "runtime_signals": signals}
        except Exception:
            return {"runnable_score": 0, "runtime_signals": []}
