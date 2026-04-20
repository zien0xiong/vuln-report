#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CNVD报告生成器 - 命令行入口
"""

import sys
import os
from pathlib import Path

import click
from colorama import init, Fore, Style

# 添加项目目录到路径
project_dir = Path(__file__).parent
sys.path.insert(0, str(project_dir))

from core.pipeline import CNVDReportPipeline
from core.state import StateManager
from core.config import config

# 初始化colorama
init()


def _normalize_proxy_url(raw: str) -> str:
    value = str(raw or "").strip()
    if not value:
        return ""
    if "://" not in value:
        return f"http://{value}"
    return value


def _apply_proxy_from_config():
    net_cfg = config.get_network_config()
    http_proxy = _normalize_proxy_url(net_cfg.get("http_proxy", ""))
    https_proxy = _normalize_proxy_url(net_cfg.get("https_proxy", ""))
    no_proxy = str(net_cfg.get("no_proxy", "") or "").strip()

    if http_proxy:
        os.environ["HTTP_PROXY"] = http_proxy
        os.environ["http_proxy"] = http_proxy
    if https_proxy:
        os.environ["HTTPS_PROXY"] = https_proxy
        os.environ["https_proxy"] = https_proxy
    if no_proxy:
        os.environ["NO_PROXY"] = no_proxy
        os.environ["no_proxy"] = no_proxy

    if http_proxy or https_proxy:
        print(f"{Fore.CYAN}[Network] 代理已启用: HTTP={http_proxy or '-'} HTTPS={https_proxy or '-'}{Style.RESET_ALL}")


def print_banner():
    """打印程序横幅"""
    banner = f"""
{Fore.CYAN}
  ____ _   _ __   _______   ____
 / ___| \ | |\ \ / /  _  \ / ___|  ___ _ ____   _____ _ __
| |   |  \| | \ V /| | | | \___ \ / _ \ '__\ \ / / _ \ '__|
| |___| |\  |  | | | |_| |  ___) |  __/ |   \ V /  __/ |
 \____|_| \_|  |_| |____/  |____/ \___|_|    \_/ \___|_|

{Style.RESET_ALL}{Fore.GREEN}CNVD报告自动生成系统 - Agent架构{Style.RESET_ALL}
"""
    print(banner)


@click.group()
def cli():
    """CNVD报告生成器"""
    pass


@cli.command()
@click.option('--input', '-i', required=True, help='输入的可信代码库报告路径')
@click.option('--resume-from', help='从指定步骤恢复 (parse/github/deploy/cvss/sqlmap/generate)')
def run(input, resume_from):
    """运行单个报告生成任务"""
    print_banner()

    # 检查配置文件和API密钥
    if not config.validate():
        print(f"{Fore.RED}错误: 请在 config.yaml 中配置 llm.api_key{Style.RESET_ALL}")
        print(f"示例:\n  llm:\n    api_key: \"your_api_key\"")
        sys.exit(1)
    _apply_proxy_from_config()

    # 检查输入文件
    input_path = Path(input)
    if not input_path.exists():
        print(f"{Fore.RED}错误: 输入文件不存在: {input}{Style.RESET_ALL}")
        sys.exit(1)

    # 创建流水线（从配置文件读取API key）
    try:
        pipeline = CNVDReportPipeline()
    except Exception as e:
        print(f"{Fore.RED}初始化失败: {e}{Style.RESET_ALL}")
        sys.exit(1)

    # 执行任务
    print(f"\n{Fore.YELLOW}开始处理: {input_path.name}{Style.RESET_ALL}\n")

    try:
        result = pipeline.run(str(input_path), resume_from=resume_from)

        if result['success']:
            print(f"\n{Fore.GREEN}✓ 任务完成!{Style.RESET_ALL}")
            print(f"  报告名称: {result['report_name']}")
            print(f"  输出文件: {result['output_file']}")
            print(f"  耗时: {result.get('duration', 0):.2f}秒")
        else:
            print(f"\n{Fore.RED}✗ 任务失败{Style.RESET_ALL}")

    except Exception as e:
        print(f"\n{Fore.RED}执行出错: {e}{Style.RESET_ALL}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


@cli.command()
@click.option('--input-dir', '-d', required=True, help='输入目录')
@click.option('--output-dir', '-o', default='workspace/output', help='输出目录')
def batch(input_dir, output_dir):
    """批量处理报告"""
    print_banner()

    # 检查配置文件和API密钥
    if not config.validate():
        print(f"{Fore.RED}错误: 请在 config.yaml 中配置 llm.api_key{Style.RESET_ALL}")
        sys.exit(1)
    _apply_proxy_from_config()

    # 检查输入目录
    input_path = Path(input_dir)
    if not input_path.exists():
        print(f"{Fore.RED}错误: 输入目录不存在: {input_dir}{Style.RESET_ALL}")
        sys.exit(1)

    # 创建流水线（从配置文件读取API key）
    pipeline = CNVDReportPipeline()

    print(f"\n{Fore.YELLOW}批量处理目录: {input_dir}{Style.RESET_ALL}\n")

    # 执行批量处理
    results = pipeline.batch_run(input_dir, output_dir)

    # 统计结果
    success_count = sum(1 for r in results if r.get('success'))
    fail_count = len(results) - success_count

    print(f"\n{Fore.GREEN}完成: 成功 {success_count}, 失败 {fail_count}{Style.RESET_ALL}")


@cli.command()
def status():
    """查看任务状态"""
    state_manager = StateManager()
    tasks = state_manager.list_tasks()

    if not tasks:
        print(f"{Fore.YELLOW}暂无任务记录{Style.RESET_ALL}")
        return

    print(f"\n{Fore.CYAN}任务列表:{Style.RESET_ALL}\n")
    print(f"{'报告名称':<40} {'状态':<12} {'更新时间':<20}")
    print("-" * 80)

    for task in tasks:
        status_color = Fore.GREEN if task['status'] == 'completed' else \
                      Fore.YELLOW if task['status'] == 'running' else Fore.RED

        print(f"{task['report_name']:<40} "
              f"{status_color}{task['status']:<12}{Style.RESET_ALL} "
              f"{task['updated_at'][:19]:<20}")


@cli.command()
@click.argument('report_name')
def logs(report_name):
    """查看指定任务的日志"""
    state_manager = StateManager()
    log_dir = state_manager.get_task_dir(report_name) / "logs"
    legacy_log_dir = Path(f"workspace/{report_name}/logs")
    if legacy_log_dir.exists() and (not log_dir.exists() or not list(log_dir.glob("*.log"))):
        log_dir = legacy_log_dir

    if not log_dir.exists():
        print(f"{Fore.RED}找不到任务日志: {report_name}{Style.RESET_ALL}")
        return

    # 列出所有日志文件
    log_files = list(log_dir.glob("*.log"))

    if not log_files:
        print(f"{Fore.YELLOW}暂无日志文件{Style.RESET_ALL}")
        return

    print(f"\n{Fore.CYAN}任务日志: {report_name}{Style.RESET_ALL}\n")

    for log_file in sorted(log_files):
        print(f"\n{Fore.YELLOW}=== {log_file.name} ==={Style.RESET_ALL}\n")

        try:
            with open(log_file, 'r', encoding='utf-8') as f:
                content = f.read()
                # 只显示最后50行
                lines = content.split('\n')
                if len(lines) > 50:
                    print(f"... ({len(lines) - 50} 行省略) ...\n")
                    print('\n'.join(lines[-50:]))
                else:
                    print(content)
        except Exception as e:
            print(f"{Fore.RED}读取日志失败: {e}{Style.RESET_ALL}")


@cli.command()
def init_dirs():
    """初始化目录结构"""
    dirs = [
        'workspace/input',
        'workspace/output',
        'workspace/logs',
        'templates'
    ]

    print(f"{Fore.CYAN}初始化目录结构...{Style.RESET_ALL}\n")

    for dir_path in dirs:
        Path(dir_path).mkdir(parents=True, exist_ok=True)
        print(f"  {Fore.GREEN}✓{Style.RESET_ALL} {dir_path}")

    print(f"\n{Fore.GREEN}目录初始化完成{Style.RESET_ALL}")


def main():
    """主入口"""
    try:
        cli()
    except KeyboardInterrupt:
        print(f"\n\n{Fore.YELLOW}用户中断{Style.RESET_ALL}")
        sys.exit(0)


if __name__ == '__main__':
    main()
