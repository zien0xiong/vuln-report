#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import unittest
from unittest.mock import patch

from agents.github_agent import GitHubSearchAgent


class GitHubSearchAgentExplicitTests(unittest.TestCase):
    def setUp(self) -> None:
        self.agent = GitHubSearchAgent(llm_client=None)

    def test_explicit_links_use_version_hint_and_network_probe(self) -> None:
        parsed_data = {
            "product_name": "Laravel CRM",
            "repository_url": "https://github.com/krayin/laravel-crm",
            "source_download_url": "https://github.com/krayin/laravel-crm/archive/refs/heads/master.zip",
            "ocr_github_urls": [
                "https://github.com/krayin/laravel-crm/archive/refs/tags/v2.1.tar.gz",
            ],
            "image_ocr_text": "https://github.com/krayin/laravel-crm/archive/refs/tags/v2.1.tar.gz",
        }

        def fake_probe(url: str):
            if url.endswith("/archive/refs/heads/2.1.zip"):
                return True, 200, ""
            return False, 404, "http_404"

        with patch.object(
            self.agent,
            "_query_repository_meta",
            return_value={"exists": True, "default_branch": "master", "full_name": "krayin/laravel-crm"},
        ), patch.object(
            self.agent, "_probe_download_url", side_effect=fake_probe
        ):
            result = self.agent._extract_explicit_github_info(parsed_data)

        self.assertIsNotNone(result)
        assert result is not None
        self.assertEqual(
            result["download_url"],
            "https://github.com/krayin/laravel-crm/archive/refs/heads/2.1.zip",
        )
        self.assertTrue(result["network_probe_success"])
        self.assertEqual(result["download_selected_by"], "network_probe")

    def test_explicit_links_fallback_when_network_unreachable(self) -> None:
        parsed_data = {
            "product_name": "Laravel CRM",
            "repository_url": "https://github.com/krayin/laravel-crm",
            "source_download_url": "https://github.com/krayin/laravel-crm/archive/refs/heads/master.zip",
            "ocr_github_urls": [
                "https://github.com/krayin/laravel-crm/archive/refs/tags/v2.1.tar.gz",
            ],
            "image_ocr_text": "version v2.1",
        }

        with patch.object(
            self.agent,
            "_query_repository_meta",
            return_value={"exists": True, "default_branch": "master", "full_name": "krayin/laravel-crm"},
        ), patch.object(
            self.agent, "_probe_download_url", return_value=(False, None, "timeout")
        ):
            result = self.agent._extract_explicit_github_info(parsed_data)

        self.assertIsNotNone(result)
        assert result is not None
        self.assertEqual(
            result["download_url"],
            "https://github.com/krayin/laravel-crm/archive/refs/heads/2.1.zip",
        )
        self.assertFalse(result["network_probe_success"])
        self.assertEqual(result["download_selected_by"], "heuristic_fallback")

    def test_select_repository_prefers_product_matched_repo(self) -> None:
        urls = [
            "https://github.com/directus/v8-archive",
            "https://github.com/krayin/laravel-crm",
            "https://github.com/krayin/laravel-crm/archive/refs/tags/v2.1.tar.gz",
        ]
        parsed_data = {
            "product_name": "Laravel CRM",
            "repository_url": "",
            "source_download_url": "",
        }

        selected = self.agent._select_repository_url(urls, parsed_data)
        self.assertEqual(selected, "https://github.com/krayin/laravel-crm")

    def test_repair_repository_and_pick_develop_branch(self) -> None:
        parsed_data = {
            "product_name": "Shlink",
            "repository_url": "https://github.com/shinkio/shlink",
            "source_download_url": "",
            "ocr_github_urls": ["https://github.com/shinkio/shlink"],
            "image_ocr_text": "shlink / shlink\ndevelop 6 Branches 151 Tags",
        }

        def fake_repo_meta(repo_url: str):
            if "shinkio/shlink" in repo_url:
                return {"exists": False, "status_code": 404}
            if "shlinkio/shlink" in repo_url:
                return {"exists": True, "status_code": 200, "default_branch": "main", "full_name": "shlinkio/shlink"}
            return {"exists": False}

        def fake_repair(repo_url: str, urls, parsed):
            return {
                "repository_url": "https://github.com/shlinkio/shlink",
                "meta": {"exists": True, "default_branch": "main", "full_name": "shlinkio/shlink"},
            }

        def fake_probe(url: str):
            if url.endswith("/archive/refs/heads/develop.zip"):
                return True, 200, ""
            return False, 404, "http_404"

        with patch.object(self.agent, "_query_repository_meta", side_effect=fake_repo_meta), patch.object(
            self.agent, "_search_repository_repair", side_effect=fake_repair
        ), patch.object(self.agent, "_probe_download_url", side_effect=fake_probe):
            result = self.agent._extract_explicit_github_info(parsed_data)

        self.assertIsNotNone(result)
        assert result is not None
        self.assertEqual(result["repository_url"], "https://github.com/shlinkio/shlink")
        self.assertTrue(result["repository_repaired"])
        self.assertEqual(
            result["download_url"], "https://github.com/shlinkio/shlink/archive/refs/heads/develop.zip"
        )
        self.assertEqual(result["download_selected_by"], "network_probe")


if __name__ == "__main__":
    unittest.main()
