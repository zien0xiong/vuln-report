# CNVD报告自动生成系统

基于大模型Agent架构的CNVD报告批量生成工具。

## 功能特性

- **ParseAgent**: 自动解析可信代码库报告，提取关键信息
- **GitHubSearchAgent**: 智能搜索GitHub源码仓库
- **DeployAgent**: 大模型驱动的智能项目部署
- **CVSSAgent**: 自动评估CVSS 3.1漏洞评分
- **SqlmapAgent**: 执行sqlmap并自动截图
- **GenerateAgent**: 生成CNVD报告，OLE对象嵌入代码文件

## 目录结构

```
cnvd_generator/
├── agents/              # Agent实现
│   ├── base_agent.py
│   ├── parse_agent.py
│   ├── github_agent.py
│   ├── deploy_agent.py
│   ├── cvss_agent.py
│   ├── sqlmap_agent.py
│   └── generate_agent.py
├── core/                # 核心模块
│   ├── logger.py        # 日志系统
│   ├── state.py         # 状态管理
│   ├── llm_client.py    # LLM客户端
│   └── pipeline.py      # 流水线控制器
├── cli.py               # 命令行接口
├── main.py              # 主入口
└── requirements.txt     # 依赖
```

## 安装依赖

```bash
cd cnvd_generator
pip install -r requirements.txt
```

## 配置API密钥

编辑 `config.yaml` 文件，配置你的API密钥：


或者将配置文件放在用户目录下 `~/.cnvd_generator/config.yaml`。

## 使用方法

### 1. 初始化目录

```bash
python cli.py init-dirs
```

### 2. 处理单个报告

```bash
python cli.py run -i "path/to/report.docx"
```

### 3. 批量处理

```bash
python cli.py batch -d "path/to/reports/"
```

### 4. 查看任务状态

```bash
python cli.py status
```

### 5. 查看日志

```bash
python cli.py logs "报告名称"
```

### 6. 从指定步骤恢复

```bash
python cli.py run -i "report.docx" --resume-from deploy
```

## 环境要求

- Windows系统
- Python 3.8+
- 预装软件:
  - PHP + Composer (用于部署PHP项目)
  - Python + pip (用于部署Python项目)
  - Node.js + npm (用于部署Node.js项目)
  - sqlmap (用于漏洞验证)

## 工作流程

1. 将可信代码库报告放入 `workspace/input/`
2. 运行 `python cli.py run -i "report.docx"`
3. 各Agent依次执行:
   - ParseAgent: 提取报告信息
   - GitHubSearchAgent: 搜索源码仓库
   - DeployAgent: 下载并部署项目
   - CVSSAgent: 评估漏洞评分
   - SqlmapAgent: 执行sqlmap+截图
   - GenerateAgent: 生成CNVD报告
4. 输出报告在 `workspace/output/`

## 日志

- 任务日志: `workspace/{report_name}/logs/`
- 错误日志: `workspace/logs/error.log`
- 主日志: `workspace/logs/cnvd_generator.log`
