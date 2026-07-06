# Cross-Platform Deployment Guide

emu-agent 和 vulnagent 可以部署在同一台机器上，无需分开 Windows/Linux。

## 三种连接模式

| 模式 | 拓扑 | 适用场景 |
|------|------|----------|
| **SameMachine** | vulnagent 和 emu-agent 在同一台机器 | 开发/测试，单机全流程 |
| **SameNetwork** | 两台机器在同一个局域网 | 实验室环境，不需 SSH |
| **SshTunnel** | 两台机器跨网络 | 远程仿真，需 SSH 密钥 |

vulnagent 自动按优先级探测，找到第一个可用后端就用哪个。

## 模式 1: SameMachine（推荐：同机部署）

```bash
# 同一台机器上
git clone https://github.com/Huange-Y/Vulnagent.git && cd Vulnagent
git checkout feat/cross-platform
pip install -e .

# 安装 QEMU
# Linux:   apt install qemu-user-static qemu-system-arm qemu-system-mips
# Windows: 安装 MSYS2 或 WSL2，然后 pacman -S mingw-w64-x86_64-qemu

# 运行 — vulnagent 自动启动 emu-agent 子进程
python -m vulnagent.cli --target firmware.img --emulation-mode agent
```

## 模式 2: SameNetwork（同网段两台机器）

```bash
# 机器 A (Linux/Windows, 装了 QEMU):
#   git clone EMUAGENT && python3 -m uvicorn server:app --host 0.0.0.0 --port 9100

# 机器 B (Windows/Linux, 跑 vulnagent):
#   config/settings.local.yaml:
#     emulation:
#       enabled: true
#       agent_host: "192.168.1.100"   # 机器 A 的 IP
#       agent_port: 9100
python -m vulnagent.cli --target firmware.img --emulation-mode agent
```

## 模式 3: SshTunnel（跨网络）

```bash
# config/settings.local.yaml:
#   emulation:
#     enabled: true
#     ssh_host: "your-vm-host"
#     ssh_port: 22
#     ssh_user: "your-user"
#     ssh_key: "~/.ssh/id_ed25519"
#     agent_port: 9100
python -m vulnagent.cli --target firmware.img --emulation-mode agent
```

## 平台兼容性

| 组件 | Windows | Linux | macOS |
|------|---------|-------|-------|
| vulnagent (cli + orchestrator) | ✅ | ✅ | ✅ |
| emu-agent (server.py) | ✅ | ✅ | ✅ |
| QEMU user-mode | MSYS2/WSL2 | apt install | brew install |
| QEMU system-mode | MSYS2/WSL2 | apt install | brew install |
| Binwalk | WSL2 | apt install | brew install |

## 与 main 分支的区别

`feat/cross-platform` 分支相比 `main`:

- `emulation_agent/backend.py`: 新增 SameMachine/SameNetwork/SshTunnel 三模式自动探测
- 原有单 SSH tunnel 模式变为可选项，不影响向后兼容
- 其余代码与 main 一致
