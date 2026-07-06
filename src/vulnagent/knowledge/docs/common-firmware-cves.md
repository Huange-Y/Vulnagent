# Common Firmware CVE Patterns

## Top Firmware Vulnerability Classes (2020-2025)

1. **CWE-78: OS Command Injection** (33% of firmware CVEs)
   - CGI scripts calling `system()`, `popen()`, `doSystem()` with user input
   - GoAhead `doSystembk`, lighttpd CGI, BusyBox httpd handlers
   
2. **CWE-798: Hardcoded Credentials** (22%)
   - Default passwords in `/etc/shadow`, `/etc/passwd`, NVRAM
   - Telnet/SSH backdoor accounts from reference designs
   - Mediatek/Ralink SDK default: admin/admin, root/12345

3. **CWE-120: Buffer Overflow** (18%)
   - `strcpy`, `sprintf`, `memcpy` with attacker-controlled size in network daemons
   - TLV parsers with unchecked length fields
   
4. **CWE-306: Missing Authentication** (12%)
   - Debug endpoints left in production builds
   - Auth bypass via empty/missing HTTP headers
   
5. **CWE-22: Path Traversal** (8%)
   - File-serving CGI that doesn't sanitize `../` sequences
   - Config export/import endpoints

## Key CVEs to Study
- CVE-2020-12753: LG smartphone bootloader command injection via USB
- CVE-2021-3156: Sudo heap overflow (Baron Samedit)
- CVE-2022-27646: NETGEAR R6700v3 buffer overflow in circled daemon
- CVE-2023-34362: MOVEit Transfer SQL injection leading to RCE
