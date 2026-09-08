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

#include "procmonEBPF_common.h"
#include <sysinternalsEBPF_helpers.c>
#include "procmonEBPF_maps.h"

// ------------------------------------------------------------------------------------------
// genericRawExit
//
// Called during a syscall exit
// ------------------------------------------------------------------------------------------
SEC("raw_tracepoint/sys_exit")
__attribute__((flatten))
int genericRawExit(struct bpf_our_raw_tracepoint_args *ctx)
{
    uint64_t pidTid = bpf_get_current_pid_tgid();
    const procmon_pt_regs *regs = (const procmon_pt_regs *)ctx->args[0];
    int pid = pidTid >> 32;

    //
    // Check all filters
    //
    if(CheckFilters(pid) == 0)
    {
        return EBPF_RET_UNUSED;
    }


    //
    // Look up the corresponding event
    //
    struct SyscallEvent* event = (struct SyscallEvent*) bpf_map_lookup_elem(&syscallsMap, &pidTid);
    if (event == NULL)
    {
        return EBPF_RET_UNUSED;
    }

    //
    // Update event fields
    //
    event->duration_ns = bpf_ktime_get_ns() - event->timestamp;

    if (bpf_probe_read(&event->ret, sizeof(int64_t), (void *)&SYSCALL_PT_REGS_RC(regs)) != 0)
    {
        BPF_PRINTK("[genericRawExit] Failed to get return code\n");
        return EBPF_RET_UNUSED;
    }

    //
    // Send event
    //
    eventOutput((void*)ctx, &eventMap, BPF_F_CURRENT_CPU, event, sizeof(struct SyscallEvent));

    bpf_map_delete_elem(&syscallsMap, &pidTid);

    return EBPF_RET_UNUSED;
}

