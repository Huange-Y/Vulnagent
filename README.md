# Vulnagent — Firmware Vulnerability Discovery Agent

固件漏洞挖掘自动化管线。输入一个目录或固件镜像，自动完成 ELF 扫描 → 漏洞发现 → CVE 去重 → 报告生成。

## Quick Start

```bash
# 安装
pip install -e .

# 配置 API key
export OPENAI_API_KEY=sk-...    # 或 DEEPSEEK_API_KEY=sk-...

# 固件审计（目录目标 — 自动 ELF 表面扫描）
python -m vulnagent.cli --target /path/to/extracted/rootfs \
  --provider deepseek --model deepseek-chat \
  --max-iterations 8 --token-budget 120000 --verbose

# 固件审计（镜像文件）
python -m vulnagent.cli --target firmware.img --scope "ARM router RCE scan"

# 检查配置
python -m vulnagent.cli --status
```

## 管线流程

```
Target (固件文件/目录)
  → Seed Triage        elf_surface_scan + file_identify + binwalk
  → BrainstormAgent    固件标记检测 → 攻击面假设
  → DiscoveryAgent     LLM 驱动的工具调用 → 漏洞发现
  → ExploitAgent       利用路径分析
  → VerificationAgent  4-layer 验证 (structural → reachability → behavioral → exploit)
  → CVE Dedup          误报过滤 + 已知CVE交叉比对 + 0day标记
  → CVSS Auto-Scoring  CVSS 3.1 五级评分
  → CVE Package        cve_submission.json (JSON 5.1) + mitre_form.txt
  → ReportAgent        Markdown 完整漏洞报告
```

## 核心功能

### ELF 表面扫描

零 LLM 调用，纯二进制字符串匹配。扫描目录下所有 ARM/MIPS/x86 ELF 文件：

- `system()` / `popen()` / `execve()` / `SYSTEM()` 动态导入检测
- `cat %s` / `rm -f %s` / `curl_cmd=%s` / `confd_cmd -c` 等 shell 命令模式
- `strpbrk()` 不完整黑名单 bypass 向量识别

输出 severity 标签 (CRITICAL/HIGH/MEDIUM/LOW)，30 秒完成全量扫描。

### 固件提取

自动识别 SquashFS, UBI/UBIFS (纯 Python 解析), uImage, tar/gzip/bzip2/xz/zip/cpio, JFFS2。

### CVE 去重管线

**Pass 1 — 误报过滤**: 自动排除 busybox symlinks (60+)、C 库、系统守护进程 (crond/dropbear/pppd/nginx)、内核模块、PAM/IPsec 插件。

**Pass 2 — 已知 CVE 交叉比对**: 匹配 Cisco RV 系列全量 17 个 CVE，精确区分 known_cve / potential_0day / false_positive。

### CVE 报告生成

自动输出 JSON 5.1 格式 (CVE Services/Vulnogram 兼容) + MITRE Web Form 文本。

### Tier 分层扫描

SURFACE → Gate → STATIC → DYNAMIC，三级门控自动推进。Tier 1 无发现自动退出，避免无效 LLM 消耗。

### QEMU 仿真验证

`qemu_elf_exec` 工具自动架构检测 (ELF e_machine) → 选择对应的 QEMU 二进制 → 执行 + strace。配合 emu-agent 可做全栈 system-mode 仿真。

### Provider 路由

按用途自动分派模型：

| 用途 | 场景 | 推荐模型 |
|------|------|----------|
| reasoning | Discovery/Exploit | deepseek-reasoner / gpt-4o |
| routing | LLM 路由决策 | deepseek-chat / gpt-4o-mini |
| critique | 质量评估 | deepseek-chat / gpt-4o-mini |
| compress | 上下文压缩 | deepseek-chat / gpt-4o-mini |

配置通过 `.myagents/settings.yaml` 或环境变量 `config/settings.local.yaml`。

### Loop 状态机

防止 Agent 长时间跑偏：round cap 检测、direction timeout、PSEUDO_COMPLETION 识别、自动约束注入。

### 上下文压缩

三层压缩：L1 Smart Truncation (零 LLM 成本) → L2 Anchored Summary (LLM + 结构保证) → L3 Hierarchical Memory (会话→持久知识)。

## CLI 参数

```
--target PATH           固件路径 (文件或目录)
--scope TEXT            审计范围描述
--provider NAME         LLM provider (openai/deepseek/openrouter)
--model NAME            推理模型名
--max-iterations N      单 agent 最大轮数 (default: 5)
--token-budget N        令牌预算 (default: 100000)
--verbose              详细输出
--json                  JSON 输出
--no-sandbox            跳过 Docker 沙盒
--emulation-mode MODE   auto/agent/direct/off (default: auto)
--status                显示 provider/model 配置
```

## 配置

LLM provider 通过 `.myagents/settings.yaml` 配置 (gitignored)：

```yaml
providers:
  deepseek:
    base_url: https://api.deepseek.com/v1
    api_key_env: DEEPSEEK_API_KEY
    models: [deepseek-chat, deepseek-reasoner]
  openai:
    base_url: https://api.openai.com/v1
    api_key_env: OPENAI_API_KEY
    models: [gpt-4o, gpt-4o-mini]
```

或复制 `config/settings.example.yaml` → `config/settings.local.yaml`。

## 与 emu-agent 协作

```bash
# VM 上启动 emu-agent
git clone https://github.com/Huange-Y/EMUAGENT.git && cd EMUAGENT
python3 -m uvicorn server:app --host 0.0.0.0 --port 9100

# vulnagent 配置 emulation 段后自动发现并调用
```

emu-agent 提供 `/api/upload_rootfs`、`/api/start_service`、`/api/probe`、`/api/exec` 接口，vulnagent 通过 HTTP 调用完成 QEMU system-mode 动态验证。

## License

MIT
