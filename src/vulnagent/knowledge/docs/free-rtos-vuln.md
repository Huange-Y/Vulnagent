# FreeRTOS Vulnerability Research

## Overview
FreeRTOS is used in millions of IoT devices. Key security considerations:

## Common Vulnerability Classes
1. **Task stack overflow**: Each task has fixed stack; `uxTaskGetStackHighWaterMark()` returns how close to overflow
2. **Queue buffer overflow**: `xQueueSend()` copies data; if sender/receiver disagree on size, overflow occurs
3. **ISR race conditions**: Interrupt Service Routines preempt tasks; data races between ISR and task code
4. **Timer callback UAF**: Software timers' callbacks can fire after the timer is deleted
5. **MPU bypass**: Memory Protection Unit regions are static; incorrect MPU configuration can allow privilege escalation

## Key Functions to Audit
- `pvPortMalloc()` / `vPortFree()` — heap allocator
- `xQueueCreate()` / `xQueueSend()` / `xQueueReceive()` — IPC
- `xTaskCreate()` / `vTaskDelete()` — task lifecycle
- `xTimerCreate()` / `xTimerStart()` — timers

## Static Analysis Tips
- Check `configMINIMAL_STACK_SIZE` in FreeRTOSConfig.h — often set dangerously low
- Look for `portTASK_FUNCTION` pragma that marks task entry points
- Queue sizes often come from compile-time constants; verify they match across sender/receiver
