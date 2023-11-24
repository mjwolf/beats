// SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause

/*
 * Copyright (C) 2022 Elasticsearch BV
 *
 * This software is dual-licensed under the BSD 2-Clause and GPL v2 licenses.
 * You may choose either one of them if you use this software.
 */

#ifndef __CGROUPS_H__
#define __CGROUPS_H__

#include "vmlinux.h"

#include "helpers.h"

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define PATH_MAX 4096
#define PATH_MAX_INDEX_MASK 4095
#define PATH_RESOLVER_MAX_COMPONENTS 100

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, u32);
    __type(value, struct kernfs_node *[PATH_RESOLVER_MAX_COMPONENTS]);
    __uint(max_entries, 1);
} path_resolver_kernfs_node_scratch_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, u32);
    __type(value, char[PATH_MAX * 2]); // Keep the verifier happy with * 2
    __uint(max_entries, 1);
} path_buf_scratch_map SEC(".maps");

/* We grab the UUID _once_ and store it in this percpu map to save stack space */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, u32);
    __type(value, char[CONTAINER_UUID_SIZE]);
    __uint(max_entries, 1);
} curr_uuid_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, char[CONTAINER_UUID_SIZE]);
    __type(value, u8);
    __uint(max_entries, 8192);
} tracked_uuids SEC(".maps");

#define KERNFS_NODE_COMPONENT_MAX_LEN 250

static int resolve_kernfs_node_to_string(char *buf, struct kernfs_node *kn)
{
    long cur = 0;
    int depth = 0, zero = 0, read_len, name_len;
    char name[KERNFS_NODE_COMPONENT_MAX_LEN];
    buf[0] = '\0';

    struct kernfs_node **kna = bpf_map_lookup_elem(&path_resolver_kernfs_node_scratch_map, &zero);
    if (!kna) {
        bpf_printk("could not get scratch area");
        goto out_err;
    }

    while (depth < PATH_RESOLVER_MAX_COMPONENTS - 1) {
        if (!kn)
            break;

        kna[depth] = kn;
        kn = BPF_CORE_READ(kn, parent);
        depth++;
    }

    while (depth > 0) {
        depth--;
        struct kernfs_node *curr = kna[depth];

        read_len = bpf_probe_read_kernel_str(&name, KERNFS_NODE_COMPONENT_MAX_LEN,
                                             (void *) BPF_CORE_READ(curr, name));
        if (read_len < 0) {
            bpf_printk("could not get read kernfs_node name: %d", read_len);
            goto out_err;
        }

        name_len = read_len - 1;
        if (name_len == 0)
            continue;

        if (cur + name_len + 1 > PATH_MAX) {
            bpf_printk("path too long");
            goto out_err;
        }

        buf[cur & PATH_MAX_INDEX_MASK] = '/';
        cur = (cur + 1) & PATH_MAX_INDEX_MASK;
        if (bpf_probe_read_kernel_str(
                buf + (cur & PATH_MAX_INDEX_MASK),
                PATH_MAX - cur > KERNFS_NODE_COMPONENT_MAX_LEN ? KERNFS_NODE_COMPONENT_MAX_LEN : 0,
                (void *) name) < 0)
            goto out_err;

        cur += name_len & PATH_MAX_INDEX_MASK;
    }

    return cur + 1; // cur does not include the \0

out_err:
    buf[0] = '\0';
    return -1;
}

static int resolve_pids_ss_cgroup_path_to_string(char *buf, const struct task_struct *task)
{
    // Since pids_cgrp_id is an enum value, we need to get it at runtime as it
    // can change kernel-to-kernel depending on the kconfig or possibly not be
    // enabled at all.
    int cgrp_id;
    if (bpf_core_enum_value_exists(enum cgroup_subsys_id, pids_cgrp_id)) {
        cgrp_id = bpf_core_enum_value(enum cgroup_subsys_id, pids_cgrp_id);
    } else {
        // Pids cgroup is not enabled on this kernel
        buf[0] = '\0';
        return -1;
    }

    struct kernfs_node *kn = BPF_CORE_READ(task, cgroups, subsys[cgrp_id], cgroup, kn);
    return resolve_kernfs_node_to_string(buf, kn);
}

static int strequal(char *s1, char *s2, size_t n)
{
    for (int i = 0; i < n; i++) {
        if (s1[i] != s2[i])
            return false;
    }

    return true;
}

static int find_longform_container_uuid(char *path)
{
    // Find the burstable or besteffort QoS container uuid from cgroup paths resembling the form
    // /kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod1acba065_6b90_4e7c_8222_ac920e8d19cc.slice/cri-containerd-58ddb344496acfeb34e5bb4d4f7bbdc6754f7a47ba59d6b45a6727f892373391.scope
    // OR where pod uuid is missing underscores
    // /kubepods.slice/kubepods-burstable.slice/kubepods-burstable-podb0c3f480769b985e94154556da4daa3a.slice/cri-containerd-184cfa2311eeef32c53b8e25f566053c1d655fa3dc5b39169d2989e3b304b046.scope

    // OR for guaranteed
    // /kubepods.slice/kubepods-pod0b37047a_3477_4ab0_9915_1c6b0e6887dd.slice/cri-containerd-4396c0cb397f033fa87d33c16f4e50fecb56b9a55e7d60784ecffd6b6627ddcc.scope

    char slice[] = ".slice";
    char burstable[] = "/kubepods-burstable";
    char besteffort[] = "/kubepods-besteffort";
    char guaranteed[] = "/kubepods";
    char containerd[] = "cri-containerd-";

    char *ptr = path;

    if (strequal(ptr, besteffort, sizeof(besteffort) - 1)) {
        ptr += 2 * sizeof(besteffort) + sizeof(slice) - 3;
    } else if (strequal(ptr, burstable, sizeof(burstable) - 1)) {
        ptr += 2 * sizeof(burstable) + sizeof(slice) - 3;
    } else if (strequal(ptr, guaranteed, sizeof(guaranteed) - 1)) {
        ptr += sizeof(guaranteed) - 1;
    } else {
        return -1;
    }

    ptr += 41; // Advance past "-pod<uuid>/"
    ptr += sizeof(slice) - 1;
    if (!strequal(ptr, containerd, sizeof(containerd) - 1)) {
        ptr -= 4; // go back 4 chars incase the uuid has no underscores
        if (!strequal(ptr, containerd, sizeof(containerd) - 1)) {
            return -1;
        }
    }
    ptr += sizeof(containerd) - 1;

    return ptr - path;
}

static int find_container_uuid(char *path)
{
    // Find the burstable or besteffort QoS container uuid from cgroup paths resembling the form
    // /kubepods/burstable/poda8d74791-ff6e-402f-8056-0ea9cb9ba1dd/48e39973315ed4356985ec3403fc57df21465e84e0c674a84bbefa361374feec

    // OR for guaranteed
    // /kubepods/podb732e43e-dc2e-4e40-802f-9277c0ea9ee4/0fd5041460ad35fc4554700003e4860c71676093154508bf15a1ff9268d9d214
    char burstable[] = "/burstable";
    char besteffort[] = "/besteffort";

    char *ptr = path;

    if (strequal(ptr, besteffort, sizeof(besteffort) - 1)) {
        ptr += sizeof(besteffort) - 1;
    } else if (strequal(ptr, burstable, sizeof(burstable) - 1)) {
        ptr += sizeof(burstable) - 1;
    }

    ptr += 41; // Advance past "/pod<uuid>/"

    return ptr - path;
}

static int fill_uuid_from_cgroup_path(char *path, char *uuid_buf)
{
    char *ptr = path;
    char kubepods[] = "/kubepods";
    char slice[] = ".slice";
    int inc;
    if (!strequal(ptr, kubepods, sizeof(kubepods) - 1))
        return -1;

    ptr += sizeof(kubepods) - 1;

    if (strequal(ptr, slice, sizeof(slice) - 1)) {
        ptr += sizeof(slice) - 1;
        inc = find_longform_container_uuid(ptr);
        if (inc < 0)
            goto cgroup_err;
    } else {
        inc = find_container_uuid(ptr);
        if (inc < 0)
            goto cgroup_err;
    }

    ptr += inc;

    cheap_bzero(uuid_buf, CONTAINER_UUID_SIZE);
    return bpf_probe_read_kernel_str(uuid_buf, CONTAINER_UUID_SIZE, ptr) == CONTAINER_UUID_SIZE
               ? 0
               : -1;
cgroup_err:
    bpf_printk("[BUG] could not parse cgroup path: %s", path);
    return -1;
}

static char *get_cnt_uuid_buf()
{
    return bpf_map_lookup_elem(&curr_uuid_map, &(int){0});
}

static int calc_cnt_uuid()
{
    struct task_struct *task = (struct task_struct *) bpf_get_current_task();

    char *full_path_buf = bpf_map_lookup_elem(&path_buf_scratch_map, &(int){0});
    if (!full_path_buf) {
        bpf_printk("[BUG] could not get kernfs path buffer");
        return -1;
    }

    if (resolve_pids_ss_cgroup_path_to_string(full_path_buf, task) == -1) {
        bpf_printk("[BUG] could not build pids cg path");
        return -1;
    }

    char *buf = get_cnt_uuid_buf();
    if (!buf) {
        bpf_printk("[BUG] could not get container UUID buffer");
        return -1;
    }

    if (fill_uuid_from_cgroup_path(full_path_buf, buf) == -1) {
        // Not a bug, can happen e.g. for stuff outside a container e.g. kubelet
        // (full_path_buf will be an empty string)
        return -1;
    }

    return 0;
}

#endif // __CGROUPS_H__
