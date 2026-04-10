#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
配置管理模块
支持从YAML配置文件读取配置
"""

import os
from pathlib import Path
from typing import Dict, Any, Optional

try:
    import yaml
    HAS_YAML = True
except ImportError:
    HAS_YAML = False


class Config:
    """配置管理器"""

    _instance = None
    _config = None

    def __new__(cls):
        """单例模式"""
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(self):
        if self._config is None:
            self._config = self._load_config()

    def _load_config(self) -> Dict[str, Any]:
        """加载配置文件"""
        # 查找配置文件
        config_paths = [
            Path("config.yaml"),
            Path("cnvd_generator/config.yaml"),
            Path.home() / ".cnvd_generator" / "config.yaml",
        ]

        config_file = None
        for path in config_paths:
            if path.exists():
                config_file = path
                break

        if config_file and HAS_YAML:
            try:
                with open(config_file, 'r', encoding='utf-8') as f:
                    config = yaml.safe_load(f)
                print(f"[Config] 已加载配置文件: {config_file}")
                return config or {}
            except Exception as e:
                print(f"[Config] 读取配置文件失败: {e}")

        # 默认配置
        return self._default_config()

    def _default_config(self) -> Dict[str, Any]:
        """默认配置"""
        return {
            "llm": {
                "api_key": os.getenv("LLM_API_KEY", ""),
                "base_url": "https://api.moonshot.cn/v1",
                "model": "kimi-k2.5"
            },
            "deployment": {
                "default_port": 18100,
                "timeout_seconds": 120,
                "health_check_interval": 2
            },
            "logging": {
                "level": "INFO",
                "max_file_size": "10MB",
                "backup_count": 5
            },
            "output": {
                "dir": "workspace/output",
                "template": "templates/cnvd_template.docx"
            }
        }

    def get(self, key: str, default: Any = None) -> Any:
        """
        获取配置值（支持点号路径）

        Args:
            key: 配置键，如 "llm.api_key"
            default: 默认值

        Returns:
            配置值
        """
        keys = key.split('.')
        value = self._config

        for k in keys:
            if isinstance(value, dict) and k in value:
                value = value[k]
            else:
                return default

        return value

    def get_llm_config(self) -> Dict[str, str]:
        """获取LLM配置"""
        return {
            "api_key": self.get("llm.api_key", ""),
            "base_url": self.get("llm.base_url", "https://api.moonshot.cn/v1"),
            "model": self.get("llm.model", "kimi-k2.5")
        }

    def get_deployment_config(self) -> Dict[str, Any]:
        """获取部署配置"""
        return {
            "default_port": self.get("deployment.default_port", 18100),
            "timeout_seconds": self.get("deployment.timeout_seconds", 120),
            "health_check_interval": self.get("deployment.health_check_interval", 2)
        }

    def get_logging_config(self) -> Dict[str, Any]:
        """获取日志配置"""
        return {
            "level": self.get("logging.level", "INFO"),
            "max_file_size": self.get("logging.max_file_size", "10MB"),
            "backup_count": self.get("logging.backup_count", 5)
        }

    def get_output_config(self) -> Dict[str, str]:
        """获取输出配置"""
        return {
            "dir": self.get("output.dir", "workspace/output"),
            "template": self.get("output.template", "templates/cnvd_template.docx")
        }

    def validate(self) -> bool:
        """验证配置是否有效"""
        llm_config = self.get_llm_config()
        if not llm_config.get("api_key"):
            print("[Config] 错误: LLM API key 未配置")
            print("[Config] 请在 config.yaml 中配置 llm.api_key")
            return False
        return True

    def reload(self):
        """重新加载配置"""
        self._config = self._load_config()


# 全局配置实例
config = Config()


if __name__ == "__main__":
    # 测试配置加载
    cfg = Config()
    print(f"API Key: {cfg.get('llm.api_key', '')[:10]}...")
    print(f"Base URL: {cfg.get('llm.base_url')}")
    print(f"Default Port: {cfg.get('deployment.default_port')}")
