/*
    Procmon-for-Linux

    Copyright (c) Microsoft Corporation

    All rights reserved.

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License along
    with this program; if not, write to the Free Software Foundation, Inc.,
    51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
*/

#ifndef PROCMON_EBPF_COMMON_H
#define PROCMON_EBPF_COMMON_H

#define PROCMON_EBPF

#define PACKET_SIZE             128
#define UDP_HASH_SIZE           (128 * 1024)


#define LINUX_MAX_EVENT_SIZE (65536 - 24)

#define MAX_BUFFER 128
#define MAX_STACK_FRAMES 32
#define MAX_PROC 512

#define CONFIG_ITEMS        1
#define MAX_PIDS           10

#define TRACER_RUNNING      0
#define TRACER_SUSPENDED    1
#define TRACER_STOP         2

#define RUNSTATE_KEY        0
#define CONFIG_PID_KEY      0

#define CONFIG_INDEX        0
#define PIDS_INDEX          1
#define RUNSTATE_INDEX      2
#define SYSCALL_INDEX       3

#define EBPF_RET_UNUSED     0

#ifdef __BPF_TRACING__
#ifdef EBPF_CO_RE
typedef struct pt_regs procmon_pt_regs;
#else
typedef struct
{
    unsigned long r15;
    unsigned long r14;
    unsigned long r13;
    unsigned long r12;
    unsigned long rbp;
    unsigned long rbx;
    unsigned long r11;
    unsigned long r10;
    unsigned long r9;
    unsigned long r8;
    unsigned long rax;
    unsigned long rcx;
    unsigned long rdx;
    unsigned long rsi;
    unsigned long rdi;
    unsigned long orig_rax;
    unsigned long rip;
    unsigned long cs;
    unsigned long eflags;
    unsigned long rsp;
    unsigned long ss;
} procmon_pt_regs;
#endif
#endif

struct SyscallEvent
{
    pid_t pid;
    uint32_t sysnum;
    uint64_t timestamp;
    uint64_t duration_ns;
    uint64_t userStack[MAX_STACK_FRAMES];
    uint64_t userStackCount;
    uint64_t ret;
    char comm[16];
    unsigned char buffer [MAX_BUFFER];
};

enum ProcmonArgTag
{
    NOTKNOWN, // Catch all for cases where arg type isn't known yet.
    INT,
    UNSIGNED_INT,
    SIZE_T,
    PID_T,
    LONG,
    UNSIGNED_LONG,
    CHAR_PTR,
    CONST_CHAR_PTR,
    FD,
    PTR,
    UINT32
};

struct SyscallSchema
{
    // We should probably just be passing the syscall number back and forth instead.
    char syscallName[100];
    // It's probably not necessary to pass this info to kernel land and we can just store
    // it in an userland only map to be used by the UI.
    char argNames[6][100];
    // The key data structure necessary to infer what needs to be done.
    enum ProcmonArgTag types[6];
    int usedArgCount;
};
#endif
