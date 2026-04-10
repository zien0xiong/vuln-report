# Repository Guidelines

## 项目结构与模块组织
- 主要代码位于 `cnvd_generator/`：  
  - `agents/`：各阶段 Agent（解析、检索、部署、评分、生成）。  
  - `core/`：配置、状态管理、流水线、日志等核心逻辑。  
  - `tests/`：`unittest` 测试用例。  
  - `templates/`：Docker/文档模板。  
  - `workspace/`：运行期输入、输出、日志与中间产物。  
- 根目录 `cnvd报告/`、`可信代码库报告/` 主要用于样例与提取结果，通常不作为功能开发目录。

## 构建、测试与开发命令
- 安装依赖：`pip install -r cnvd_generator/requirements.txt`  
  安装运行与测试所需 Python 包。
- 初始化目录：`python cnvd_generator/cli.py init-dirs`  
  创建 `workspace` 等必需目录。
- 单报告执行：`python cnvd_generator/cli.py run -i "cnvd报告/xxx.docx"`  
  触发完整流水线处理单个报告。
- 批量执行：`python cnvd_generator/cli.py batch -d "cnvd报告"`  
  对目录内报告批量处理。
- 查看状态：`python cnvd_generator/cli.py status`
- 运行测试：`python -m unittest discover -s cnvd_generator/tests -v`

## 编码风格与命名约定
- Python 文件统一 UTF-8、4 空格缩进。
- 命名规则：函数/变量/模块使用 `snake_case`，类使用 `PascalCase`。
- Agent 文件建议保持 `*_agent.py` 命名；新增 Agent 时沿用现有阶段化设计。
- 路径处理优先使用 `pathlib.Path`，避免硬编码平台相关路径。

## 测试指南
- 测试框架为 `unittest`，测试文件命名为 `test_*.py`。
- 新增或修改 `agents`/`core`/CLI 行为时，至少补充：  
  1) 正常流程；2) 异常分支；3) Windows 路径相关边界。
- 提交前本地执行完整测试，并在 PR 描述中给出关键验证命令与结果摘要。

## 提交与 Pull Request 规范
- 当前工作区快照未包含 `.git` 历史；默认采用 Conventional Commits（如 `feat:`, `fix:`, `docs:`）。
- PR 需包含：变更目的、核心改动、验证步骤、潜在风险与回滚方式。
- 涉及 CLI 或部署行为变化时，附关键日志片段或命令输出。

## 安全与配置提示
- 严禁提交真实密钥（如 `cnvd_generator/config.yaml` 中的 API Key）。
- 优先使用环境变量（如 `LLM_API_KEY`）或本地未跟踪配置覆盖。
- `cnvd_generator/workspace/` 下运行产物、下载源码包、临时日志不应纳入版本控制。
