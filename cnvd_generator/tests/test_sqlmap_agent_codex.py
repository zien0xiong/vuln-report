#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import unittest
from pathlib import Path

from agents.sqlmap_agent import SqlmapAgent


class SqlmapAgentCodexTests(unittest.TestCase):
    def setUp(self) -> None:
        self.agent = SqlmapAgent(llm_client=None)
        self.agent.auth_cfg = {
            "login_path": "/admin/auth/login",
            "username": "admin",
            "password": "admin",
            "username_field": "username",
            "password_field": "password",
            "csrf_field": "_token",
        }

    def test_collect_evidence_keywords_positive(self) -> None:
        text = """
        [INFO] parameter '_sort[cast]' appears to be injectable
        [INFO] back-end DBMS is MySQL
        """
        hits = self.agent._collect_evidence_keywords(text)
        self.assertIn("appears_injectable", hits)
        self.assertIn("back_end_dbms", hits)

    def test_collect_evidence_keywords_negative(self) -> None:
        text = "all tested parameters do not appear to be injectable"
        hits = self.agent._collect_evidence_keywords(text)
        self.assertEqual(hits, [])

    def test_collect_evidence_keywords_false_positive_should_not_confirm(self) -> None:
        text = """
        [INFO] checking if the injection point on (custom) POST parameter 'JSON datatype' is a false positive
        [WARNING] false positive or unexploitable injection point detected
        [WARNING] (custom) POST parameter 'JSON datatype' does not seem to be injectable
        """
        hits = self.agent._collect_evidence_keywords(text)
        self.assertEqual(hits, [])

    def test_build_auth_profile_missing(self) -> None:
        self.agent.auth_cfg = {"login_path": "/admin/auth/login"}
        profile = self.agent._build_auth_profile("http://127.0.0.1:18100")
        self.assertIn("sqlmap.auth.username", profile["missing_fields"])
        self.assertIn("sqlmap.auth.password", profile["missing_fields"])

    def test_parse_codex_result(self) -> None:
        message = (
            '{"status":"success","auth_used":true,'
            '"command":"sqlmap -r test.txt","return_code":0,'
            '"vulnerability_confirmed":true,'
            '"confirmation_source":"sqlmap","evidence_level":"confirmed",'
            '"evidence_keywords":["appears_injectable"],'
            '"negative_evidence_snippets":["none"],'
            '"log_path":"workspace/test.log","screenshot_path":"workspace/test.png",'
            '"failure_reason":"","notes":"ok"}'
        )
        parsed = self.agent._parse_codex_result(message, "")
        self.assertEqual(parsed["status"], "success")
        self.assertTrue(parsed["auth_used"])
        self.assertTrue(parsed["vulnerability_confirmed"])
        self.assertEqual(parsed["confirmation_source"], "sqlmap")
        self.assertEqual(parsed["evidence_level"], "confirmed")
        self.assertEqual(parsed["log_path"], "workspace/test.log")

    def test_build_prompt_contains_principle_and_steps(self) -> None:
        prompt = self.agent._build_codex_sqlmap_prompt(
            base_url="http://127.0.0.1:18100",
            route_path="/admin/auth/roles",
            parsed_data={
                "vulnerability_principle": "orderByRaw with unsanitized cast",
                "reproduction_steps": ["login", "capture request", "run sqlmap"],
            },
            deployment={"project_path": r"D:\demo\project", "compose_services": ["app", "db", "sqlmap"]},
            sqlmap_command='sqlmap -r test.txt -p "_sort[cast]" --batch',
            command_reference='sqlmap -r test.txt -p "_sort[cast]" --batch',
            auth_profile=self.agent._build_auth_profile("http://127.0.0.1:18100"),
            request_path=Path("workspace/test.txt"),
            container_request_path=Path("workspace/test_container.txt"),
            result_log_path=Path("workspace/sqlmap_output.txt"),
            result_screenshot_path=Path("workspace/sqlmap_result.png"),
            prefer_container=True,
            sqlmap_timeout=900,
            target_parameter="_sort[cast]",
            previous_attempts=[],
        )
        self.assertIn("orderByRaw with unsanitized cast", prompt)
        self.assertIn("run sqlmap", prompt)
        self.assertIn("Username: admin", prompt)
        self.assertIn("REFERENCE ONLY", prompt)

    def test_target_parameter_match(self) -> None:
        log = "[WARNING] POST parameter 'dbname' does not seem to be injectable"
        matched = self.agent._is_target_parameter_match(log, "dbname", {})
        self.assertTrue(matched)

    def test_select_screenshot_text_prefers_heuristic_block(self) -> None:
        log = "\n".join(
            [
                "[INFO] parsing request",
                "[INFO] heuristic (basic) test shows that POST parameter 'x' might be injectable",
                "[INFO] testing for SQL injection on POST parameter 'x'",
                "line a",
                "line b",
                "line c",
                "line d",
                "line e",
                "line f",
                "line g",
                "line h",
                "line i",
                "line j",
                "line k",
                "line l",
                "[WARNING] false positive or unexploitable injection point detected",
            ]
        )
        excerpt = self.agent._select_screenshot_text(log, preferred="heuristic")
        self.assertIn("might be injectable", excerpt.lower())
        self.assertNotIn("false positive or unexploitable", excerpt.lower())


if __name__ == "__main__":
    unittest.main()
