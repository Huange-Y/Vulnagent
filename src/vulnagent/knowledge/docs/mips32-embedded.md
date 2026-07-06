# MIPS32 Embedded Firmware Analysis

## Architecture Overview
MIPS32 is the dominant architecture in consumer routers and IoT devices (Mediatek/Ralink, Qualcomm Atheros, Broadcom). Key characteristics for vulnerability research:

## Calling Convention
- Arguments: $a0-$a3 (registers 4-7)
- Return value: $v0-$v1 (registers 2-3)
- Return address: $ra (register 31)
- Stack pointer: $sp (register 29)
- Delay slots: instruction after branch ALWAYS executes

## Common Vulnerability Patterns
1. **Stack buffer overflow**: `addiu $sp, $sp, -N` allocates frame; `sw $ra, N($sp)` saves return address
2. **Dangerous functions**: `sprintf` (no size), `strcpy` (no bounds), `system()` in CGI handlers
3. **ROP gadgets**: Look for `jr $ra` preceded by `lw $ra, N($sp); addiu $sp, $sp, M` — perfect stack pivot
4. **GOT overwrite**: MIPS uses lazy binding; overwriting GOT entries redirects PLT calls

## Emulation Tips
- Use `qemu-mipsel-static -L rootfs/ binary` for user-mode
- Set `LD_LIBRARY_PATH` to rootfs `/lib:/usr/lib`
- MIPS executables may be big-endian (mips) or little-endian (mipsel)
- The Malta board is the default system-mode target
