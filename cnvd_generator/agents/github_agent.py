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
from urllib.parse import quote, urlparse

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

        explicit = self._extract_explicit_github_info(parsed_data)
        if explicit:
            probe_mode = explicit.get("download_selected_by", "unknown")
            probe_ok = bool(explicit.get("network_probe_success", False))
            self.logger.info(
                f"使用报告内显式链接，跳过GitHub搜索: {explicit.get('repository_url')} | {explicit.get('download_url')} | select={probe_mode} | probe_ok={probe_ok}"
            )
            output_path = self._get_output_path(state, "github_result.json")
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(explicit, f, ensure_ascii=False, indent=2)
            return {"output_path": str(output_path), "data": explicit}

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

    def _extract_explicit_github_info(self, parsed_data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        urls: List[str] = []
        for key in ("source_download_url", "repository_url"):
            value = str(parsed_data.get(key, "") or "").strip()
            if value:
                urls.append(value)

        raw_ocr = parsed_data.get("ocr_github_urls", [])
        if isinstance(raw_ocr, list):
            urls.extend([str(x).strip() for x in raw_ocr if str(x).strip()])

        raw_text = str(parsed_data.get("raw_text", "") or "")
        urls.extend(self._extract_github_urls_from_text(raw_text))
        image_ocr_text = str(parsed_data.get("image_ocr_text", "") or "")
        if image_ocr_text:
            urls.extend(self._extract_github_urls_from_text(image_ocr_text))

        urls = self._dedupe_keep_order(urls)
        if not urls:
            return None

        repository_url = self._select_repository_url(urls, parsed_data)

        if not repository_url:
            return None

        original_repository_url = repository_url
        repository_url, repo_meta = self._ensure_valid_repository_url(repository_url, urls, parsed_data)
        if not repository_url:
            return None

        default_branch = str(repo_meta.get("default_branch", "") or "").strip() or "main"
        version_hints = self._collect_version_hints(urls, parsed_data, repository_url)
        branch_hints = self._collect_branch_hints(urls, parsed_data, repository_url, default_branch)
        archive_urls = [
            self._normalize_url(u)
            for u in urls
            if self._looks_like_github_archive_url(self._normalize_url(u))
            and self._repo_url_from_github_url(self._normalize_url(u)) == repository_url
        ]
        candidate_urls = self._build_explicit_download_candidates(
            repository_url=repository_url,
            default_branch=default_branch,
            branch_hints=branch_hints,
            version_hints=version_hints,
            explicit_archive_urls=archive_urls,
        )
        selected_download_url, probe = self._pick_reachable_download_url(candidate_urls)
        probe_ok = bool(selected_download_url)
        selected_by = "network_probe" if probe_ok else "heuristic_fallback"
        if not selected_download_url:
            selected_download_url = self._choose_fallback_download_url(
                candidates=candidate_urls,
                branch_hints=branch_hints,
                version_hints=version_hints,
                explicit_archive_urls=archive_urls,
                default_branch=default_branch,
            )

        version = self._infer_version_from_archive_url(selected_download_url) or default_branch
        selected_branch = self._infer_branch_from_archive_url(selected_download_url)
        return {
            "repository_url": repository_url,
            "download_url": selected_download_url,
            "version": version,
            "confidence": 0.99,
            "source": "report_explicit_url",
            "download_selected_by": selected_by,
            "network_probe_success": probe_ok,
            "download_candidates": candidate_urls,
            "download_probe": probe,
            "repository_info": {
                "full_name": str(repo_meta.get("full_name", "") or "/".join(repository_url.rstrip("/").split("/")[-2:])),
                "description": str(repo_meta.get("description", "") or ""),
                "stars": int(repo_meta.get("stars", 0) or 0),
                "language": str(repo_meta.get("language", "") or ""),
                "default_branch": default_branch,
            },
            "selected_branch_or_ref": selected_branch or version,
            "repository_repaired": repository_url != original_repository_url,
            "repository_original": original_repository_url,
        }

    def _choose_fallback_download_url(
        self,
        candidates: List[str],
        branch_hints: List[str],
        version_hints: List[str],
        explicit_archive_urls: List[str],
        default_branch: str,
    ) -> str:
        if not candidates:
            return ""

        branch_set = {str(item or "").strip().lower() for item in branch_hints if str(item or "").strip()}
        version_set: set[str] = set()
        for item in version_hints:
            token = str(item or "").strip().lower()
            if not token:
                continue
            version_set.add(token)
            if token.startswith("v"):
                version_set.add(token[1:])
            else:
                version_set.add(f"v{token}")
        explicit_set = {str(item or "").strip().lower() for item in explicit_archive_urls if str(item or "").strip()}
        has_non_default_hint = any(
            item not in {"main", "master", str(default_branch or "").strip().lower()} for item in branch_set if item
        )

        best_url = candidates[0]
        best_score = -10_000
        for url in candidates:
            low = str(url or "").lower()
            score = 0

            # 明确链接加分
            if low in explicit_set:
                score += 15

            # 分支候选加分
            inferred_branch = self._infer_branch_from_archive_url(low).lower()
            if inferred_branch and inferred_branch in branch_set:
                if inferred_branch in {"main", "master", str(default_branch or "").strip().lower()}:
                    score += 8
                else:
                    score += 40

            # 版本候选加分（优先 heads/{version}.zip）
            inferred_ref = self._infer_version_from_archive_url(low).lower()
            if inferred_ref and inferred_ref in version_set:
                if "/refs/heads/" in low:
                    score += 50
                elif "/refs/tags/" in low:
                    score += 28

            if low.endswith(".tar.gz"):
                score -= 4

            # 默认分支适度兜底
            if low.endswith(f"/refs/heads/{str(default_branch or '').lower()}.zip"):
                score += 10
            if low.endswith("/refs/heads/main.zip") or low.endswith("/refs/heads/master.zip"):
                score += 6

            # 若存在非默认提示，压低 main/master
            if has_non_default_hint and (
                low.endswith("/refs/heads/main.zip") or low.endswith("/refs/heads/master.zip")
            ):
                score -= 18

            if score > best_score:
                best_score = score
                best_url = url

        return best_url

    def _select_repository_url(self, urls: List[str], parsed_data: Dict[str, Any]) -> str:
        configured_repo = self._repo_url_from_github_url(str(parsed_data.get("repository_url", "") or ""))
        if configured_repo:
            return configured_repo

        configured_archive_repo = self._repo_url_from_github_url(
            str(parsed_data.get("source_download_url", "") or "")
        )
        if configured_archive_repo:
            return configured_archive_repo

        repo_candidates = self._dedupe_keep_order(
            [self._repo_url_from_github_url(self._normalize_url(url)) for url in urls]
        )
        repo_candidates = [repo for repo in repo_candidates if repo]
        if not repo_candidates:
            return ""
        if len(repo_candidates) == 1:
            return repo_candidates[0]

        product_name = str(parsed_data.get("product_name", "") or "").lower()
        product_tokens = [token for token in re.findall(r"[a-z0-9]+", product_name) if len(token) >= 3]

        best_repo = repo_candidates[0]
        best_score = -1
        for repo in repo_candidates:
            score = 0
            repo_low = repo.lower()
            for token in product_tokens:
                if token in repo_low:
                    score += 3
            for raw in urls:
                normalized = self._normalize_url(raw)
                if self._repo_url_from_github_url(normalized) != repo:
                    continue
                score += 1
                if self._looks_like_github_archive_url(normalized):
                    score += 1
            if score > best_score:
                best_score = score
                best_repo = repo
        return best_repo

    def _ensure_valid_repository_url(
        self,
        repository_url: str,
        urls: List[str],
        parsed_data: Dict[str, Any],
    ) -> tuple[str, Dict[str, Any]]:
        normalized = self._repo_url_from_github_url(repository_url)
        if not normalized:
            return "", {}

        current_meta = self._query_repository_meta(normalized)
        if current_meta.get("exists"):
            return normalized, current_meta

        repaired = self._search_repository_repair(normalized, urls, parsed_data)
        if repaired:
            repaired_url = str(repaired.get("repository_url", "") or "")
            repaired_meta = dict(repaired.get("meta", {}) or {})
            if repaired_url:
                return repaired_url, repaired_meta

        return normalized, current_meta

    def _query_repository_meta(self, repository_url: str) -> Dict[str, Any]:
        try:
            parts = repository_url.rstrip("/").split("/")
            if len(parts) < 2:
                return {"exists": False}
            owner = parts[-2]
            repo = parts[-1]
            api_url = f"{self.github_api}/repos/{owner}/{repo}"
            headers = {"Accept": "application/vnd.github.v3+json", "User-Agent": "CNVD-Report-Generator"}
            response = requests.get(api_url, headers=headers, timeout=15)
            if response.status_code != 200:
                return {"exists": False, "status_code": int(response.status_code)}
            data = response.json()
            return {
                "exists": True,
                "status_code": 200,
                "full_name": str(data.get("full_name", "") or ""),
                "default_branch": str(data.get("default_branch", "") or "main"),
                "description": str(data.get("description", "") or ""),
                "language": str(data.get("language", "") or ""),
                "stars": int(data.get("stargazers_count", 0) or 0),
            }
        except Exception:
            return {"exists": False}

    def _search_repository_repair(
        self,
        repository_url: str,
        urls: List[str],
        parsed_data: Dict[str, Any],
    ) -> Optional[Dict[str, Any]]:
        repo_names = self._collect_repo_name_candidates(urls, parsed_data, repository_url)
        if not repo_names:
            return None

        product_text = " ".join(
            [
                str(parsed_data.get("product_name", "") or ""),
                str(parsed_data.get("product_description", "") or ""),
                str(parsed_data.get("raw_text", "") or "")[:1000],
                str(parsed_data.get("image_ocr_text", "") or "")[:1000],
            ]
        ).lower()
        product_tokens = [t for t in re.findall(r"[a-z0-9]+", product_text) if len(t) >= 3]

        source_parts = repository_url.rstrip("/").split("/")
        original_owner = source_parts[-2].lower() if len(source_parts) >= 2 else ""
        original_repo = source_parts[-1].lower() if len(source_parts) >= 1 else ""

        best: Optional[Dict[str, Any]] = None
        best_score = -10_000
        headers = {"Accept": "application/vnd.github.v3+json", "User-Agent": "CNVD-Report-Generator"}
        search_url = f"{self.github_api}/search/repositories"

        for repo_name in repo_names:
            params = {
                "q": f"{repo_name} in:name",
                "sort": "stars",
                "order": "desc",
                "per_page": 10,
            }
            try:
                response = requests.get(search_url, headers=headers, params=params, timeout=20)
                if response.status_code != 200:
                    continue
                items = response.json().get("items", [])
                if not isinstance(items, list):
                    continue
            except Exception:
                continue

            for item in items:
                html_url = str(item.get("html_url", "") or "").strip()
                full_name = str(item.get("full_name", "") or "").strip()
                if not html_url or not full_name:
                    continue

                name = str(item.get("name", "") or "").lower()
                owner = str(item.get("owner", {}).get("login", "") or "").lower()
                full_low = full_name.lower()
                score = 0

                if name == repo_name.lower():
                    score += 10
                if name == original_repo:
                    score += 4
                if owner == original_owner:
                    score += 2
                if original_owner and self._levenshtein_distance(owner, original_owner) <= 2:
                    score += 2

                token_hits = 0
                for token in product_tokens[:40]:
                    if token in full_low:
                        token_hits += 1
                score += min(token_hits, 6)

                score += min(int(item.get("stargazers_count", 0) or 0) // 1000, 5)

                if score > best_score:
                    best_score = score
                    best = {
                        "repository_url": html_url,
                        "meta": {
                            "exists": True,
                            "status_code": 200,
                            "full_name": full_name,
                            "default_branch": str(item.get("default_branch", "") or "main"),
                            "description": str(item.get("description", "") or ""),
                            "language": str(item.get("language", "") or ""),
                            "stars": int(item.get("stargazers_count", 0) or 0),
                        },
                    }

        return best

    def _collect_repo_name_candidates(
        self,
        urls: List[str],
        parsed_data: Dict[str, Any],
        repository_url: str,
    ) -> List[str]:
        names: List[str] = []
        for raw in urls:
            normalized = self._normalize_url(raw)
            repo_url = self._repo_url_from_github_url(normalized)
            if not repo_url:
                continue
            parts = repo_url.rstrip("/").split("/")
            if parts:
                names.append(parts[-1])

        base_parts = repository_url.rstrip("/").split("/")
        if base_parts:
            names.append(base_parts[-1])

        text_blob = "\n".join(
            [
                str(parsed_data.get("image_ocr_text", "") or ""),
                str(parsed_data.get("raw_text", "") or ""),
            ]
        )
        for match in re.findall(r"\b([A-Za-z0-9_.-]{2,})\s*/\s*([A-Za-z0-9_.-]{2,})\b", text_blob):
            _, repo = match
            names.append(str(repo).strip())

        deduped = self._dedupe_keep_order(names)
        return [name for name in deduped if 2 <= len(name) <= 80]

    def _levenshtein_distance(self, a: str, b: str) -> int:
        x = str(a or "")
        y = str(b or "")
        if x == y:
            return 0
        if not x:
            return len(y)
        if not y:
            return len(x)
        prev = list(range(len(y) + 1))
        for i, cx in enumerate(x, 1):
            curr = [i]
            for j, cy in enumerate(y, 1):
                ins = curr[j - 1] + 1
                delete = prev[j] + 1
                replace = prev[j - 1] + (0 if cx == cy else 1)
                curr.append(min(ins, delete, replace))
            prev = curr
        return prev[-1]

    def _collect_version_hints(
        self,
        urls: List[str],
        parsed_data: Dict[str, Any],
        repository_url: str,
    ) -> List[str]:
        hints: List[str] = []
        for raw in urls:
            url = self._normalize_url(raw)
            if self._repo_url_from_github_url(url) != repository_url:
                continue
            ver = self._infer_version_from_archive_url(url)
            if ver and self._is_version_like(ver):
                hints.append(ver)
        return self._dedupe_keep_order(hints)

    def _collect_branch_hints(
        self,
        urls: List[str],
        parsed_data: Dict[str, Any],
        repository_url: str,
        default_branch: str,
    ) -> List[str]:
        hints: List[str] = []
        for raw in urls:
            url = self._normalize_url(raw)
            if self._repo_url_from_github_url(url) != repository_url:
                continue
            branch = self._infer_branch_from_archive_url(url)
            if self._is_branch_like(branch):
                hints.append(branch)

        text_blob = "\n".join(
            [
                str(parsed_data.get("image_ocr_text", "") or ""),
                str(parsed_data.get("raw_text", "") or ""),
            ]
        )
        for token in re.findall(r"\b([A-Za-z0-9._/-]+)\s+\d+\s+branches\b", text_blob, flags=re.I):
            if self._is_branch_like(token):
                hints.append(token)

        for token in re.findall(r"\b(develop|dev|main|master|next|nightly)\b", text_blob, flags=re.I):
            if self._is_branch_like(token):
                hints.append(token)

        if self._is_branch_like(default_branch):
            hints.append(default_branch)
        return self._dedupe_keep_order(hints)

    def _build_explicit_download_candidates(
        self,
        repository_url: str,
        default_branch: str,
        branch_hints: List[str],
        version_hints: List[str],
        explicit_archive_urls: List[str],
    ) -> List[str]:
        candidates: List[str] = []

        # 1) 先尝试分支提示（如 develop/main/master）
        for branch in branch_hints:
            value = str(branch or "").strip()
            if not self._is_branch_like(value):
                continue
            candidates.append(f"{repository_url}/archive/refs/heads/{value}.zip")

        # 2) 再尝试从 URL 里抽到的版本提示
        for hint in version_hints:
            normalized = hint.strip()
            with_v = normalized if normalized.lower().startswith("v") else f"v{normalized}"
            no_v = normalized[1:] if normalized.lower().startswith("v") else normalized
            variants = [no_v, with_v]
            for v in variants:
                candidates.append(f"{repository_url}/archive/refs/heads/{v}.zip")
            for v in variants:
                candidates.append(f"{repository_url}/archive/refs/tags/{v}.zip")
                candidates.append(f"{repository_url}/archive/refs/tags/{v}.tar.gz")

        # 3) 最后尝试报告中显式出现的归档链接
        candidates.extend(explicit_archive_urls)

        # 4) 默认分支回退
        candidates.append(f"{repository_url}/archive/refs/heads/{default_branch}.zip")
        if default_branch.lower() != "main":
            candidates.append(f"{repository_url}/archive/refs/heads/main.zip")
        if default_branch.lower() != "master":
            candidates.append(f"{repository_url}/archive/refs/heads/master.zip")

        return self._dedupe_keep_order(candidates)

    def _pick_reachable_download_url(self, candidates: List[str]) -> tuple[str, List[Dict[str, Any]]]:
        probe_results: List[Dict[str, Any]] = []
        for url in candidates:
            ok, status, error = self._probe_download_url(url)
            probe_results.append({"url": url, "ok": ok, "status_code": status, "error": error})
            if ok:
                return url, probe_results
        return "", probe_results

    def _probe_download_url(self, url: str) -> tuple[bool, Optional[int], str]:
        try:
            response = requests.head(
                url,
                timeout=10,
                allow_redirects=True,
                headers={"User-Agent": "CNVD-Report-Generator"},
            )
            code = int(response.status_code)
            if code < 400:
                return True, code, ""
            # 部分站点不支持 HEAD，补一次 GET 探测
            if code in (403, 405):
                response_get = requests.get(
                    url,
                    timeout=12,
                    allow_redirects=True,
                    stream=True,
                    headers={"User-Agent": "CNVD-Report-Generator"},
                )
                code_get = int(response_get.status_code)
                response_get.close()
                return code_get < 400, code_get, ""
            return False, code, f"http_{code}"
        except Exception as error:
            return False, None, str(error)

    def _is_version_like(self, value: str) -> bool:
        text = str(value or "").strip()
        if not text:
            return False
        # 版本提示至少包含一个点号与数字（避免把 v8-archive 的 v8 当版本）
        if not re.search(r"\d+\.\d+", text):
            return False
        # 排除 IP 地址
        if re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", text):
            return False
        try:
            major = int(text.lstrip("vV").split(".")[0])
            if major > 50:
                return False
        except Exception:
            pass
        return True

    def _is_branch_like(self, value: str) -> bool:
        text = str(value or "").strip()
        if not text:
            return False
        if len(text) > 64:
            return False
        low = text.lower()
        if low in {"branch", "branches", "tag", "tags", "release", "releases"}:
            return False
        if low.startswith("http://") or low.startswith("https://"):
            return False
        if re.search(r"\s", text):
            return False
        if re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", text):
            return False
        if re.fullmatch(r"\d+", text):
            return False
        return True

    def _extract_github_urls_from_text(self, text: str) -> List[str]:
        pattern = r"https?://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(?:/[^\s<>'\"，。；;\)\]]*)?"
        found = re.findall(pattern, str(text or ""), flags=re.I)
        return [u.strip().rstrip(".,);]}>") for u in found if str(u).strip()]

    def _normalize_url(self, url: str) -> str:
        value = str(url or "").strip().rstrip(".,);]}>")
        return value

    def _repo_url_from_github_url(self, url: str) -> str:
        try:
            parsed = urlparse(str(url or "").strip())
            if parsed.netloc.lower() != "github.com":
                return ""
            parts = [p for p in parsed.path.split("/") if p]
            if len(parts) < 2:
                return ""
            return f"https://github.com/{parts[0]}/{parts[1]}"
        except Exception:
            return ""

    def _looks_like_github_archive_url(self, url: str) -> bool:
        low = str(url or "").lower()
        if "github.com/" not in low:
            return False
        return (
            "/archive/" in low
            or "/zipball/" in low
            or "/tarball/" in low
            or low.endswith(".zip")
            or low.endswith(".tar.gz")
        )

    def _infer_version_from_archive_url(self, url: str) -> str:
        low = str(url or "")
        m = re.search(r"/archive/refs/tags/([^/]+)\.(?:zip|tar\.gz)$", low, flags=re.I)
        if m:
            return m.group(1)
        m = re.search(r"/archive/refs/heads/([^/]+)\.(?:zip|tar\.gz)$", low, flags=re.I)
        if m:
            return m.group(1)
        return ""

    def _infer_branch_from_archive_url(self, url: str) -> str:
        low = str(url or "")
        m = re.search(r"/archive/refs/heads/([^/]+)\.(?:zip|tar\.gz)$", low, flags=re.I)
        if m:
            return m.group(1)
        return ""

    def _query_default_branch(self, repository_url: str) -> str:
        try:
            parts = repository_url.rstrip("/").split("/")
            if len(parts) < 2:
                return ""
            owner = parts[-2]
            repo = parts[-1]
            api_url = f"{self.github_api}/repos/{owner}/{repo}"
            headers = {"Accept": "application/vnd.github.v3+json", "User-Agent": "CNVD-Report-Generator"}
            response = requests.get(api_url, headers=headers, timeout=15)
            if response.status_code != 200:
                return ""
            data = response.json()
            return str(data.get("default_branch", "") or "").strip()
        except Exception:
            return ""

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
