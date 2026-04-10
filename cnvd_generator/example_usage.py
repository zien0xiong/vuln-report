#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CNVD报告生成器 - 使用示例

确保已在 config.yaml 中配置 API key
"""

from pathlib import Path

from core.pipeline import CNVDReportPipeline
from core.state import StateManager
from core.config import config


def example_single_report():
    """单报告处理示例"""
    # 验证配置
    if not config.validate():
        print("错误: 请在 config.yaml 中配置 llm.api_key")
        return

    # 创建流水线（自动从配置文件读取API key）
    pipeline = CNVDReportPipeline()

    # 处理单个报告
    input_file = "可信代码库报告/DCAT-Admin_admin_auth_roles存在SQL注入漏洞.docx"

    try:
        result = pipeline.run(input_file)
        print(f"成功: {result}")
    except Exception as e:
        print(f"失败: {e}")


def example_check_status():
    """查看任务状态示例"""
    pipeline = CNVDReportPipeline()

    # 查看所有任务
    tasks = pipeline.list_tasks()
    for task in tasks:
        print(f"{task['report_name']}: {task['status']}")


def example_with_custom_config():
    """使用自定义配置示例"""
    from core.llm_client import LLMClient

    # 方式1: 直接传入API key
    llm = LLMClient(api_key="your_custom_api_key")
    pipeline = CNVDReportPipeline()

    # 方式2: 使用配置文件中的配置
    print(f"API Key: {config.get('llm.api_key', '')[:10]}...")
    print(f"Base URL: {config.get('llm.base_url')}")
    print(f"Default Port: {config.get('deployment.default_port')}")


if __name__ == '__main__':
    example_single_report()
