#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Configuration management."""

import os
from pathlib import Path
from typing import Any, Dict

try:
    import yaml
    HAS_YAML = True
except ImportError:
    HAS_YAML = False


class Config:
    """Singleton configuration loader."""

    _instance = None
    _config = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(self):
        if self._config is None:
            self._config = self._load_config()

    def _load_config(self) -> Dict[str, Any]:
        config_paths = [
            Path("config.yaml"),
            Path("cnvd_generator/config.yaml"),
            Path.home() / ".cnvd_generator" / "config.yaml",
        ]

        config_file = next((p for p in config_paths if p.exists()), None)
        if config_file and HAS_YAML:
            try:
                with open(config_file, "r", encoding="utf-8") as f:
                    cfg = yaml.safe_load(f)
                print(f"[Config] 已加载配置文件: {config_file}")
                return cfg or {}
            except Exception as error:
                print(f"[Config] 读取配置文件失败: {error}")

        return self._default_config()

    def _default_config(self) -> Dict[str, Any]:
        return {
            "llm": {
                "api_key": os.getenv("LLM_API_KEY", ""),
                "base_url": "https://api.moonshot.cn/v1",
                "model": "kimi-k2.5",
                "vision_model": "qwen-vl-max",
            },
            "deployment": {
                "default_port": 18100,
                "timeout_seconds": 120,
                "health_check_interval": 2,
            },
            "sqlmap": {
                "timeout_seconds": 900,
                "codex_timeout_seconds": 2400,
                "route_probe_timeout_seconds": 12,
                "adaptive": {
                    "max_attempts": 1,
                    "retry_only_if_strict_flags": False,
                    "min_time_sec": 5,
                    "min_timeout_seconds": 20,
                    "min_retries": 2,
                    "add_random_agent": True,
                },
                "strategy": {
                    "command_policy": "reference_only",
                    "success_rule": "parameter_and_evidence",
                    "invalid_json_retry_once": True,
                },
                "auth": {
                    "login_path": "/admin/auth/login",
                    "username": "",
                    "password": "",
                    "username_field": "username",
                    "password_field": "password",
                    "csrf_field": "_token",
                },
            },
            "logging": {
                "level": "INFO",
                "max_file_size": "10MB",
                "backup_count": 5,
            },
            "network": {
                "http_proxy": "",
                "https_proxy": "",
                "no_proxy": "127.0.0.1,localhost",
            },
            "output": {
                "dir": "workspace/output",
                "template": "templates/cnvd_template.docx",
            },
        }

    def get(self, key: str, default: Any = None) -> Any:
        keys = key.split(".")
        value: Any = self._config
        for k in keys:
            if isinstance(value, dict) and k in value:
                value = value[k]
            else:
                return default
        return value

    def get_llm_config(self) -> Dict[str, str]:
        return {
            "api_key": self.get("llm.api_key", ""),
            "base_url": self.get("llm.base_url", "https://api.moonshot.cn/v1"),
            "model": self.get("llm.model", "kimi-k2.5"),
            "vision_model": self.get("llm.vision_model", "qwen-vl-max"),
        }

    def get_deployment_config(self) -> Dict[str, Any]:
        return {
            "default_port": self.get("deployment.default_port", 18100),
            "timeout_seconds": self.get("deployment.timeout_seconds", 120),
            "health_check_interval": self.get("deployment.health_check_interval", 2),
        }

    def get_logging_config(self) -> Dict[str, Any]:
        return {
            "level": self.get("logging.level", "INFO"),
            "max_file_size": self.get("logging.max_file_size", "10MB"),
            "backup_count": self.get("logging.backup_count", 5),
        }

    def get_sqlmap_config(self) -> Dict[str, Any]:
        return {
            "timeout_seconds": self.get("sqlmap.timeout_seconds", 900),
            "codex_timeout_seconds": self.get("sqlmap.codex_timeout_seconds", 2400),
            "route_probe_timeout_seconds": self.get("sqlmap.route_probe_timeout_seconds", 12),
                "adaptive": {
                "max_attempts": self.get("sqlmap.adaptive.max_attempts", 1),
                "retry_only_if_strict_flags": self.get("sqlmap.adaptive.retry_only_if_strict_flags", False),
                "min_time_sec": self.get("sqlmap.adaptive.min_time_sec", 5),
                "min_timeout_seconds": self.get("sqlmap.adaptive.min_timeout_seconds", 20),
                "min_retries": self.get("sqlmap.adaptive.min_retries", 2),
                "add_random_agent": self.get("sqlmap.adaptive.add_random_agent", True),
            },
            "strategy": {
                "command_policy": self.get("sqlmap.strategy.command_policy", "reference_only"),
                "success_rule": self.get("sqlmap.strategy.success_rule", "parameter_and_evidence"),
                "invalid_json_retry_once": self.get("sqlmap.strategy.invalid_json_retry_once", True),
            },
            "auth": {
                "login_path": self.get("sqlmap.auth.login_path", "/admin/auth/login"),
                "username": self.get("sqlmap.auth.username", ""),
                "password": self.get("sqlmap.auth.password", ""),
                "username_field": self.get("sqlmap.auth.username_field", "username"),
                "password_field": self.get("sqlmap.auth.password_field", "password"),
                "csrf_field": self.get("sqlmap.auth.csrf_field", "_token"),
            },
        }

    def get_output_config(self) -> Dict[str, str]:
        return {
            "dir": self.get("output.dir", "workspace/output"),
            "template": self.get("output.template", "templates/cnvd_template.docx"),
        }

    def get_network_config(self) -> Dict[str, str]:
        return {
            "http_proxy": self.get("network.http_proxy", ""),
            "https_proxy": self.get("network.https_proxy", ""),
            "no_proxy": self.get("network.no_proxy", "127.0.0.1,localhost"),
        }

    def validate(self) -> bool:
        llm_cfg = self.get_llm_config()
        if not llm_cfg.get("api_key"):
            print("[Config] 错误: LLM API key 未配置")
            print("[Config] 请在 config.yaml 中配置 llm.api_key")
            return False
        return True

    def reload(self):
        self._config = self._load_config()


config = Config()


if __name__ == "__main__":
    cfg = Config()
    print(f"API Key: {cfg.get('llm.api_key', '')[:10]}...")
    print(f"Base URL: {cfg.get('llm.base_url')}")
    print(f"Default Port: {cfg.get('deployment.default_port')}")
