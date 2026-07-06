# VxWorks RTOS Vulnerability Research

## Overview
VxWorks by Wind River, used in aerospace, industrial control, networking (Cisco, Juniper), medical devices.

## Security Architecture
- Flat memory model (no MMU on many targets) — no process isolation
- WDB agent: remote debugging on UDP 17185, often left enabled without auth
- RPC: remote procedure calls for inter-task communication
- 256 priority levels, preemptive scheduling

## Common Vulnerabilities
1. WDB agent RCE (CWE-798): Remote memory read/write, task spawning. CVE-2015-7599.
2. RPC buffer overflow (CWE-120): Parameter marshaling overflows
3. Task priority inversion DoS (CWE-400)
4. File system symlink attacks (CWE-61): dosFs path traversal
5. Hardcoded credentials: Default target/target, admin/admin for telnet/ftp

## Key Audit Targets
- wdbConfig / wdbTask — WDB agent
- rpcTask — RPC handlers
- dosFsLib — file operations
- telnetdLib / ftpdLib — network services
- /tgtsvr — target server mount point

## Emulation Tips
- QEMU supports VxWorks on x86, ARM, PPC
- Probe WDB: echo "wdb" | nc -u target 17185
- Check default passwords: target/target, admin/admin