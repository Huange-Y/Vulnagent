# Zephyr RTOS Vulnerability Research

## Overview
Zephyr is a Linux Foundation RTOS used in many modern IoT devices.

## Security Architecture
- Memory protection: MPU (Cortex-M) or MMU (Cortex-A)
- Thread isolation: user/kernel space separation
- Stack canaries: optional, controlled by `CONFIG_STACK_CANARIES`
- ASLR: not available on most Cortex-M targets

## Vulnerability Classes
1. **System call validation bypass**: Zephyr syscalls go through `_arch_syscall_invoke`; validation happens in generated code
2. **Network stack bugs**: Zephyr has full IP stack (IPv4/IPv6/TCP/UDP/CoAP/LwM2M)
3. **Bluetooth stack**: Zephyr's BLE stack is complex; GATT, SMP, L2CAP each have their own parsers
4. **Sensor drivers**: I2C/SPI sensor drivers often lack bounds checking on register reads
5. **CoAP parser vulnerabilities**: Constrained Application Protocol parsers are frequent targets

## Key Configurations
- `CONFIG_USERSPACE`: Enables kernel/user separation
- `CONFIG_STACK_SENTINEL`: Guards against stack overflow
- `CONFIG_BT` / `CONFIG_NETWORKING`: Enable BT/network stacks
