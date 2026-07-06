# ThreadX RTOS Vulnerability Research

## Overview
ThreadX (Azure RTOS) by Microsoft, widely used in IoT, wearables. Picokernel architecture, ~2KB footprint.

## Security Architecture
- Picokernel: minimal core, everything else optional
- No MMU/MPU by default (ThreadX Modules add optional MPU)
- Preemption-threshold scheduling (unique to ThreadX)
- No built-in memory protection between threads

## Common Vulnerabilities
1. Thread stack overflow: Fixed stack per thread, no runtime overflow detection
2. Queue use-after-free: Message queues pass pointers; sender free before receiver = UAF
3. Mutex priority inversion: Priority inheritance exists but incorrect usage still deadlocks
4. Timer callback overflow: Long timer callbacks starve other timers
5. Memory pool corruption: No integrity checks on freed byte/block pools

## Key Functions to Audit
- tx_thread_create() — stack size allocation
- tx_queue_send() / tx_queue_receive() — message passing
- tx_mutex_create() / tx_mutex_get() — mutex ops
- tx_timer_create() / tx_timer_activate() — timer lifecycle
- tx_byte_pool_allocate() / tx_byte_pool_release() — heap management
- _txe_thread_stack_build() — internal stack setup

## Static Analysis Tips
- Enumerate all tx_thread_create calls, verify stack sizes
- Check tx_queue_send paired with tx_queue_receive across threads
- Timer callbacks must not block — scan for tx_mutex_get inside timers
- Validate block pool sizes against actual allocation requests