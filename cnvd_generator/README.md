# CNVD 报告自动生成系统

基于 Agent 流水线的 CNVD 报告生成工具，支持从“可信代码库报告”自动完成解析、源码定位、部署、漏洞验证和报告生成。

---

## 1. 功能概览

- **ParseAgent**：解析 Word 报告，提取漏洞信息（含图片 OCR 辅助 GitHub 链接识别）
- **GitHubSearchAgent**：确定仓库与下载链接
- **DeployAgent（Codex 驱动）**：下载源码、尝试部署并输出访问信息
- **CVSSAgent**：生成 CVSS 评分信息
- **SqlmapAgent（Codex 驱动）**：执行漏洞验证、保存命令输出与截图
- **GenerateAgent**：生成 CNVD Word 报告，并尝试插入 OLE 漏洞代码文件

---

## 2. 项目结构（核心）

```text
cnvd_generator/
├─ agents/                 # 各阶段 Agent
├─ core/                   # 配置/状态/日志/流水线
├─ tools/                  # 工具模块（read_word、OLE辅助等）
├─ templates/              # 报告模板与 docker 模板
├─ tests/                  # unittest 测试
├─ workspace/              # 运行产物（任务目录、日志、输出）
├─ cli.py                  # CLI 入口
└─ requirements.txt        # Python 依赖
```

> 说明：`read_word` 已迁移为模块 `cnvd_generator/tools/read_word.py`。

---

## 3. 环境要求

- Windows（OLE 嵌入依赖 Windows COM）
- Python 3.8+
- 可用的 LLM API Key
- **Docker Desktop + Docker Compose**（部署阶段依赖系统 Docker CLI）
- **Codex CLI**（Deploy/Sqlmap 阶段调用 `codex exec`）

> 注意：Docker 是系统依赖，不是 Python `requirements.txt` 依赖。

---

## 4. 安装

在仓库根目录执行：

```bash
pip install -r cnvd_generator/requirements.txt
```

---

## 5. 配置

优先级（高 -> 低）：
1. `config.yaml`
2. `cnvd_generator/config.yaml`
3. `~/.cnvd_generator/config.yaml`

推荐做法：
- API Key 放环境变量 `LLM_API_KEY` 或本地配置文件
- 不要把真实密钥写进 README 或提交到仓库

示例（`cnvd_generator/config.example.yaml`）：

```yaml
llm:
  api_key: "your_api_key_here"
  base_url: "https://dashscope.aliyuncs.com/compatible-mode/v1"
  model: "qwen-max"
  vision_model: "qwen-vl-max"
```

---

## 6. 常用命令（从仓库根目录）

### 初始化目录

```bash
python cnvd_generator/cli.py init-dirs
```

### 单报告执行

```bash
python cnvd_generator/cli.py run -i "可信代码库报告/xxx.docx"
```

### 从指定步骤恢复

```bash
python cnvd_generator/cli.py run -i "可信代码库报告/xxx.docx" --resume-from sqlmap
```

可选步骤：`parse / github / deploy / cvss / sqlmap / generate`

### 批量执行

```bash
python cnvd_generator/cli.py batch -d "可信代码库报告"
```

### 查看状态与日志

```bash
python cnvd_generator/cli.py status
python cnvd_generator/cli.py logs "报告名称"
```

---

## 7. read_word 工具用法

模块方式（推荐）：

```bash
python -m cnvd_generator.tools.read_word "可信代码库报告/xxx.docx"
```

可选输出目录：

```bash
python -m cnvd_generator.tools.read_word "可信代码库报告/xxx.docx" "workspace/tmp/read_word_out"
```

---

## 8. 运行产物位置

- 任务状态：`workspace/<规范化任务名>/state.json`
- 各阶段产物：
  - `01_parse/parsed.json`
  - `02_github/github_result.json`
  - `03_sourcecode/deployment.json`
  - `04_cvss/cvss_result.json`
  - `05_sqlmap/sqlmap_result.json` + 截图/文本
- 最终报告：`workspace/output/<报告名>.docx`
- 日志：`workspace/<规范化任务名>/logs/` 与 `workspace/logs/`

---

## 9. 故障排查建议

- 提示 API key 未配置：检查 `llm.api_key` 或 `LLM_API_KEY`
- `--resume-from` 失败：需保证前置步骤已完成
- 部署/验证卡住：先看 `logs` 和对应阶段目录下 `codex_exec_*.log`
- Docker 相关失败：先确认本机 `docker` 与 `docker compose` 命令可用
