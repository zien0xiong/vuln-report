#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import unittest
from unittest.mock import patch

from agents.deploy_agent import DeployAgentReAct


class DeployAgentReActTests(unittest.TestCase):
    def setUp(self) -> None:
        self.pipeline_logger_patch = patch("agents.deploy_agent.PipelineLogger")
        pipeline_logger_cls = self.pipeline_logger_patch.start()
        pipeline_logger_cls.return_value.logger = type(
            "DummyLogger",
            (),
            {"debug": lambda *args, **kwargs: None, "warning": lambda *args, **kwargs: None},
        )()
        pipeline_logger_cls.return_value.info = lambda *args, **kwargs: None
        self.addCleanup(self.pipeline_logger_patch.stop)
        self.agent = DeployAgentReAct(llm_client=None)

    def test_resolve_path_avoids_double_prefix(self) -> None:
        base = r"workspace\demo\03_sourcecode\repo"
        raw = r"workspace\demo\03_sourcecode\repo\.env"
        result = self.agent._resolve_path(base, raw)
        self.assertEqual(str(result).lower(), raw.lower())

    def test_classify_php_mismatch(self) -> None:
        output = "Your lock file does not contain a compatible set. brick/math 0.14.8 requires php ^8.2"
        err = self.agent._classify_command_error("composer install --no-dev", output, 2)
        self.assertEqual(err["error_type"], "php_version_mismatch")
        self.assertTrue(err["can_retry"])

    def test_get_environment_action(self) -> None:
        context = {"source_path": r"workspace\demo\03_sourcecode\repo"}
        obs = self.agent._execute_action(
            {"type": "get_environment", "keys": ["PATH"]},
            context,
        )
        self.assertEqual(obs["status"], "success")
        self.assertIn("PATH", obs["output"])

    def test_progress_marks_deps_ready(self) -> None:
        context = {
            "source_path": r"workspace\demo\03_sourcecode\repo",
            "progress": {"deps_ready": False, "env_ready": False, "service_started": False, "service_running": False},
            "action_failures": {},
            "error_buckets": {},
            "stagnation_count": 0,
        }
        action = {"type": "run_command", "command": "composer install --no-dev"}
        obs = {"status": "success", "output": ""}
        self.agent._update_context_after_observation(action, obs, context)
        self.assertTrue(context["progress"]["deps_ready"])


if __name__ == "__main__":
    unittest.main()
