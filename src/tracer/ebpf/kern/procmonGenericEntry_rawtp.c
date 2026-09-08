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

#ifdef EBPF_CO_RE
#include "vmlinux.h"
typedef __u32 __uint32_t;
typedef __u64 __uint64_t;
#define _STDINT_H
#else
#include <linux/version.h>
#include <linux/bpf.h>
#include <linux/socket.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <linux/fcntl.h>
#include <sys/socket.h>
#include <linux/string.h>
#include <asm/ptrace.h>
#include <linux/types.h>
#include <stdint.h>
#endif

#include <bpf_helpers.h>
#include <bpf_core_read.h>
#include <asm/unistd_64.h>

#include <sysinternalsEBPF_common.h>
#include "procmonEBPF_common.h"
#include <sysinternalsEBPF_helpers.c>
#include "procmonEBPF_maps.h"


#define bpf_probe(dsc, size, src, str)                              \
    if (str)                                                        \
        bpf_probe_read_str((void*)dsc, size, (const void*)src);     \
    else                                                            \
        bpf_probe_read((void*)dsc, size, src);


// ------------------------------------------------------------------------------------------
// PopulateArguments
//
// Populates the event with the arguments for the syscall.
// ------------------------------------------------------------------------------------------
__attribute__((always_inline))
static inline int PopulateArguments(enum ProcmonArgTag type, unsigned long arg, struct SyscallEvent * event, unsigned int* offset_ptr)
{
    unsigned int len = 0;
    unsigned int str = 0;
    unsigned long src = arg;

    if (type == INT || type == LONG)
    {
        len = sizeof(long);
        src = (unsigned long)&arg;
    }
    else if (type == UNSIGNED_INT || type == UNSIGNED_LONG || type == SIZE_T || type == PID_T || type == PTR)
    {
        len = sizeof(unsigned long);
        src = (unsigned long)&arg;
    }
    else if (type == CHAR_PTR || type == CONST_CHAR_PTR)
    {
        len = MAX_BUFFER / 6;
        str = 1;
    }
    else if (type == FD)
    {
        len = MAX_BUFFER / 6;
        str = 1;
        char buff[len];
    }
    else if (type == UINT32)
    {
        len = sizeof(uint32_t);
        src = (unsigned long)&arg;
    }
    else
    {
        // Do nothing here....
    }

    if (*offset_ptr + len >= MAX_BUFFER)
        return -1;

    if (!src)
        return -1;

    bpf_probe(event->buffer + *offset_ptr, len, (void *)src, str)
    *offset_ptr += len;

    return 0;
}

// ------------------------------------------------------------------------------------------
// set_eventArgs
//
// Populates the event with the arguments for the syscall.
// ------------------------------------------------------------------------------------------
__attribute__((always_inline))
static inline bool set_eventArgs(unsigned long *a, const struct pt_regs *regs)
{
    int ret = 0;
    ret |= bpf_probe_read(&a[0], sizeof(a[0]), &SYSCALL_PT_REGS_PARM1(regs));
    ret |= bpf_probe_read(&a[1], sizeof(a[1]), &SYSCALL_PT_REGS_PARM2(regs));
    ret |= bpf_probe_read(&a[2], sizeof(a[2]), &SYSCALL_PT_REGS_PARM3(regs));
    ret |= bpf_probe_read(&a[3], sizeof(a[3]), &SYSCALL_PT_REGS_PARM4(regs));
    ret |= bpf_probe_read(&a[4], sizeof(a[4]), &SYSCALL_PT_REGS_PARM5(regs));
    ret |= bpf_probe_read(&a[5], sizeof(a[5]), &SYSCALL_PT_REGS_PARM6(regs));
    if (!ret)
        return true;
    else
        return false;
}

// ------------------------------------------------------------------------------------------
// GetRunningState
//
// Returns the running state
// ------------------------------------------------------------------------------------------
__attribute__((always_inline))
static inline uint64_t GetRunningState()
{
    uint64_t *state = NULL;
    int rkey = RUNSTATE_KEY;

    state = (uint64_t*)bpf_map_lookup_elem(&runstate, &rkey);
    if(state == NULL)
    {
        return -1;
    }

    return *state;
}


// ------------------------------------------------------------------------------------------
// MatchPidFilter
//
// Checks if the specified pid matches the pid filter
// ------------------------------------------------------------------------------------------
__attribute__((always_inline))
static inline int IsProcmon()
{
    char comm[16] = {0};
    bpf_get_current_comm(comm, sizeof(comm));

    if (comm[0] == 'p' && comm[1] == 'r' && comm[2] == 'o' && comm[3] == 'c' && comm[4] == 'm' && comm[5] == 'o' && comm[6] == 'n')
    {
        return 1;
    }

    return 0;
}

// ------------------------------------------------------------------------------------------
// MatchPidFilter
//
// Checks if the specified pid matches the pid filter
// ------------------------------------------------------------------------------------------
__attribute__((always_inline))
static inline int MatchPidFilter(int pid)
{
    for(int i=0; i<MAX_PIDS; i++)
    {
        uint32_t key = i;
        int* pidMapItem = (int*)bpf_map_lookup_elem(&pids, &key);
        if(pidMapItem)
        {
            int foundPid = *pidMapItem;

            if(foundPid == pid)
            {
                return 1;
            }

            if(foundPid == -1)
            {
                //
                // if the first element is -1, then we are in "include all" mode
                //
                if(i == 0)
                {
                    return 1;
                }

                break;              // we can bail early since -1 indicates we've reached the end of the pid items in the map
            }
        }
        else
        {
            break;
        }
    }

    return 0;
}

// ------------------------------------------------------------------------------------------
// CheckFilters
//
// Checks all filters to see if the event should be processed
// ------------------------------------------------------------------------------------------
__attribute__((always_inline))
static inline int CheckFilters(int pid)
{
    //
    // Check if we are in procmon
    //
    if(IsProcmon() == 1)
    {
        return 0;
    }

    //
    // Check to make sure we are in a running state
    //
    int runstate = GetRunningState();
    if(runstate != 0)
    {
        return 0;
    }

    //
    // If a pid filter has been specified, check if the pid matches
    //
    if(MatchPidFilter(pid) == 0)
    {
        return 0;
    }

    return 1;
}


// ------------------------------------------------------------------------------------------
// genericRawEnter
//
// Called during a syscall enter
// ------------------------------------------------------------------------------------------
SEC("raw_tracepoint/sys_enter")
__attribute__((flatten))
int genericRawEnter(struct bpf_our_raw_tracepoint_args *ctx)
{
    uint32_t syscall = ctx->args[1];
    uint32_t cpuId = bpf_get_smp_processor_id();
    uint64_t pidTid = bpf_get_current_pid_tgid();
    int pid = pidTid >> 32;
    struct pt_regs* regs = NULL;

    //
    // Check all filters
    //
    if(CheckFilters(pid) == 0)
    {
        return EBPF_RET_UNUSED;
    }

    //
    // Get the syscall details
    //
    struct SyscallSchema* schema = bpf_map_lookup_elem(&syscalls, &syscall);
    if(schema == NULL)
    {
        BPF_PRINTK("[genericRawEnter] Failed to get syscall schema %d.", syscall);
        return EBPF_RET_UNUSED;
    }

    //
    // Get temp storage to build up the event
    //
    struct SyscallEvent* sysEntry = bpf_map_lookup_elem(&eventStorageMap, &cpuId);
    if (!sysEntry)
    {
        BPF_PRINTK("[genericRawEnter] Failed to get storage for syscall event.");
        return EBPF_RET_UNUSED;
    }

    //
    // Populate the event
    //
    sysEntry->pid = pid;
    sysEntry->sysnum = ctx->args[1];
    bpf_get_current_comm(&sysEntry->comm, sizeof(sysEntry->comm));
    sysEntry->userStackCount = bpf_get_stack(ctx, &sysEntry->userStack, MAX_STACK_FRAMES * sizeof(uint64_t), BPF_F_USER_STACK) / sizeof(uint64_t);
    sysEntry->timestamp = bpf_ktime_get_ns();

    regs = (struct pt_regs *)ctx->args[0];
    unsigned long a[8];
    if (!set_eventArgs(a, regs))
    {
        BPF_PRINTK("[genericRawEnter] Failed to set_eventArgs\n");
        return EBPF_RET_UNUSED;
    }

    unsigned int offset = 0;
    for (int i = 0; i < 6; i++)
    {
        if(PopulateArguments(schema->types[i], a[i], sysEntry, &offset) || i >= schema->usedArgCount)
        {
            break;
        }
    }

    //
    // Store the event to be retrieved and updated on exit
    //
    if (bpf_map_update_elem(&syscallsMap, &pidTid, sysEntry, BPF_ANY) != UPDATE_OKAY)
    {
        BPF_PRINTK("[genericRawEnter] Failed to update syscalls map\n");
        return EBPF_RET_UNUSED;
    }

    return EBPF_RET_UNUSED;
}