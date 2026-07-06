# ARM32 (ARMv7) Embedded Firmware Analysis

## Architecture Overview
ARM is ubiquitous in modern IoT: Qualcomm IPQ40xx, Broadcom BCM53xx, NXP i.MX, STM32MP1. Two instruction sets exist: ARM (32-bit) and Thumb (16-bit).

## Calling Convention (AAPCS)
- Arguments: r0-r3
- Return value: r0
- Link register: lr (r14) — holds return address
- Frame pointer: fp (r11) — optional
- Stack pointer: sp (r13)

## Common Vulnerability Patterns
1. **Stack overflow**: `push {r4-r7, lr}` saves lr on stack; overflow overwrites it
2. **Thumb gadgets**: `pop {r0-r4, pc}` is the most powerful ROP gadget in Thumb mode
3. **BX LR**: Every function ends with `bx lr` — but gadgets can pop lr from a controlled stack then `bx lr`
4. **Heap exploitation**: ARM has PC-relative addressing; heap metadata attacks are architecture-agnostic

## Emulation Tips
- Use `qemu-arm-static -L rootfs/ binary`
- Thumb functions have LSB=1 in their address
- The `virt` machine is the go-to for system-mode
