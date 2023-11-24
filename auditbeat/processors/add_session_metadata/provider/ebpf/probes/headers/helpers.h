// SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause

/*
 * Copyright (C) 2022 Elasticsearch BV
 *
 * This software is dual-licensed under the BSD 2-Clause and GPL v2 licenses.
 * You may choose either one of them if you use this software.
 */

#ifndef __HELPER_H__
#define __HELPER_H__

#include "vmlinux.h"

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "proto.h"

// Limits on large things we send up as variable length parameters.
//
// These should be kept _well_ under half the size of the event_buffer_map or
// the verifier will be unhappy due to bounds checks. Putting a cap on these
// things also prevents any one process from DoS'ing and filling up the
// ringbuffer with super rapid-fire events.
#define ARGV_MAX 20480
#define ENV_MAX 40960
#define TTY_OUT_MAX 8192

#define PATH_MAX 4096
#define PATH_MAX_INDEX_MASK 4095
#define PATH_RESOLVER_MAX_COMPONENTS 100

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, u32);
    __type(value, char[16 * 1024]);
    __uint(max_entries, 1);
} zeros_map SEC(".maps");

// bzero, but cheap w.r.t. verifier states. This is because instead of a loop
// (each state of which would have to be explored), we use a bpf_probe_read
// from a buffer known to contain zeros (BPF_MAP_TYPE_ARRAY elements are
// zero-initialized), thus we just need a handful of instructions to zero an
// entire buffer.
static void cheap_bzero(char *buf, size_t size)
{
    void *z = bpf_map_lookup_elem(&zeros_map, &(uint32_t){0});
    if (!z) {
        bpf_printk("[BUG] Could not lookup in zeros map");
        return;
    }

    bpf_probe_read(buf, size, z);
}

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, u32);
    __type(value, struct dentry *[PATH_RESOLVER_MAX_COMPONENTS]);
    __uint(max_entries, 1);
} path_resolver_dentry_scratch_map SEC(".maps");

// Resolve a struct path to a string. Returns the size of the constructed path
// string, including the null terminator.
static size_t resolve_path_to_string(char *buf, const struct path *path)
{
    long size = 0;
    bool truncated = true;
    struct vfsmount *curr_vfsmount = BPF_CORE_READ(path, mnt);

    // All struct vfsmount's are stored in a struct mount. We need fields in
    // the struct mount to continue the dentry walk when we hit the root of a
    // mounted filesystem.
    struct mount *mnt = container_of(curr_vfsmount, struct mount, mnt);
    struct dentry *curr_dentry = BPF_CORE_READ(path, dentry);
    struct dentry **dentry_arr;

    // Ensure we make buf an empty string early up here so if we exit with any
    // sort of error, we won't leave garbage in it if it's uninitialized
    buf[0] = '\0';

    u32 zero = 0;
    if (!(dentry_arr = bpf_map_lookup_elem(&path_resolver_dentry_scratch_map, &zero))) {
        bpf_printk("Could not get path resolver scratch area");
        goto out_err;
    }

    // Loop 1, follow the dentry chain (up to a maximum of
    // PATH_RESOLVER_MAX_COMPONENTS) and store pointers to each dentry in
    // dentry_arr
    for (int i = 0; i < PATH_RESOLVER_MAX_COMPONENTS; i++) {
        if (BPF_CORE_READ(mnt, mnt_parent) == mnt) {
            // We've reached the mount namespace root if mnt->parent points
            // back to mnt. Fill the rest of the array with NULLs so it's
            // ignored
            truncated = false;
            dentry_arr[i] = NULL;
            continue;
        }

        struct dentry *parent = BPF_CORE_READ(curr_dentry, d_parent);
        if (curr_dentry == parent || curr_dentry == BPF_CORE_READ(curr_vfsmount, mnt_root)) {

            // We've hit the root of a mounted filesystem. The dentry walk must
            // be continued from mnt_mountpoint in the current struct mount.
            // Also update curr_vfsmount to point to the parent filesystem root.
            curr_dentry = (struct dentry *) BPF_CORE_READ(mnt, mnt_mountpoint);
            mnt = BPF_CORE_READ(mnt, mnt_parent);
            curr_vfsmount = (struct vfsmount *) &mnt->mnt;

            // We might be at another fs root here (in which case
            // curr_dentry->d_name will have "/", we need to go up another
            // level to get an actual component name), so fill the dentry
            // pointer array at this spot with NULL so it's ignored in the next
            // loop and continue to check the above condition again.
            dentry_arr[i] = NULL;
            continue;
        }

        dentry_arr[i] = curr_dentry;
        curr_dentry = parent;
    }

    if (truncated) {
        // Use a relative path eg. ./some/dir as a best effort if we have
        // more components than PATH_RESOLVER_MAX_COMPONENTS.
        buf[0] = '.';
        size = 1;
    }

    // Loop 2, walk the array of dentry pointers (in reverse order) and
    // copy the d_name component of each one into buf, separating with '/'
    for (int i = PATH_RESOLVER_MAX_COMPONENTS - 1; i >= 0; i--) {
        struct dentry *dentry = dentry_arr[i];
        if (dentry == NULL)
            continue;

        struct qstr component = BPF_CORE_READ(dentry, d_name);
        if (size + component.len + 1 > PATH_MAX) {
            bpf_printk("path under construction is too long: %s", buf);
            goto out_err;
        }

        // Note that even though the value of size is guaranteed to be
        // less than PATH_MAX_INDEX_MASK here, we have to apply the bound again
        // before using it an index into an array as if it's spilled to the
        // stack by the compiler, the verifier bounds information will not be
        // retained after each bitwise and (this only carries over when stored
        // in a register).
        buf[size & PATH_MAX_INDEX_MASK] = '/';
        size = (size + 1) & PATH_MAX_INDEX_MASK;

        int ret = bpf_probe_read_kernel_str(buf + (size & PATH_MAX_INDEX_MASK),
                                            PATH_MAX > size ? PATH_MAX - size : 0,
                                            (void *) component.name);

        if (ret > 0) {
            size += ((ret - 1) & PATH_MAX_INDEX_MASK);
        } else {
            bpf_printk("could not read d_name at %p, current path %s", component.name, buf);
            goto out_err;
        }
    }

    // Special case: root directory. If the path is "/", the above loop will
    // not have run and thus path_string will be an empty string. We handle
    // that case here.
    if (buf[0] == '\0') {
        buf[0] = '/';
        buf[1] = '\0';
        size = 1;
    }

    return size + 1; // size does not include the \0

out_err:
    buf[0] = '\0';
    return 1;
}

static bool is_kernel_thread(const struct task_struct *task)
{
    // All kernel threads are children of kthreadd, which always has pid 2
    // except on some ancient kernels (2.4x)
    // https://unix.stackexchange.com/a/411175
    return BPF_CORE_READ(task, group_leader, real_parent, tgid) == 2;
}

static bool is_thread_group_leader(const struct task_struct *task)
{
    return BPF_CORE_READ(task, pid) == BPF_CORE_READ(task, tgid);
}

static void pid_info__fill(struct pid_info *pi, const struct task_struct *task)
{
    pi->tid = BPF_CORE_READ(task, pid);
    pi->tgid = BPF_CORE_READ(task, tgid);
    pi->ppid = BPF_CORE_READ(task, group_leader, real_parent, tgid);
    pi->pgid = BPF_CORE_READ(task, group_leader, signal, pids[PIDTYPE_PGID], numbers[0].nr);
    pi->sid = BPF_CORE_READ(task, group_leader, signal, pids[PIDTYPE_SID], numbers[0].nr);
    pi->start_time_ns = BPF_CORE_READ(task, group_leader, start_time);

    struct pid *pid = BPF_CORE_READ(task, group_leader, thread_pid);
    if (pid) {
        uint32_t level = BPF_CORE_READ(pid, level);
        struct pid_namespace *ns = BPF_CORE_READ(pid, numbers[level].ns);
        struct pid *tgid_ptr = BPF_CORE_READ(task, group_leader, signal, pids[PIDTYPE_TGID]);

        unsigned int ns_level = (ns == NULL ? 0 : BPF_CORE_READ(ns, level));
        if (tgid_ptr && ns_level <= BPF_CORE_READ(tgid_ptr, level)) {
            struct upid upid = BPF_CORE_READ(tgid_ptr, numbers[ns_level]);
            if (ns == NULL || upid.ns == ns)
                pi->vpid = upid.nr;
        }
    }
}

static void tty_dev__fill(struct tty_dev *tty_dev, const struct tty_struct *tty)
{
    tty_dev->major = BPF_CORE_READ(tty, driver, major);
    tty_dev->minor = BPF_CORE_READ(tty, driver, minor_start);
    tty_dev->minor += BPF_CORE_READ(tty, index);

    struct winsize winsize = BPF_CORE_READ(tty, winsize);
    struct tty_winsize ws = {};
    ws.rows = winsize.ws_row;
    ws.cols = winsize.ws_col;
    tty_dev->winsize = ws;

    struct ktermios termios = BPF_CORE_READ(tty, termios);
    struct tty_termios t = {};
    t.c_iflag = termios.c_iflag;
    t.c_oflag = termios.c_oflag;
    t.c_lflag = termios.c_lflag;
    t.c_cflag = termios.c_cflag;
    tty_dev->termios = t;
}

static void ctty__fill(struct tty_dev *ctty, const struct task_struct *task)
{
    struct tty_struct *tty = BPF_CORE_READ(task, signal, tty);
    tty_dev__fill(ctty, tty);
}

static void cred_info__fill(struct cred_info *ci, const struct task_struct *task)
{
    ci->ruid = BPF_CORE_READ(task, cred, uid.val);
    ci->euid = BPF_CORE_READ(task, cred, euid.val);
    ci->suid = BPF_CORE_READ(task, cred, suid.val);
    ci->rgid = BPF_CORE_READ(task, cred, gid.val);
    ci->egid = BPF_CORE_READ(task, cred, egid.val);
    ci->sgid = BPF_CORE_READ(task, cred, sgid.val);

    if (bpf_core_field_exists(task->cred->cap_permitted.cap)) {
        kernel_cap_t dest;

        dest.cap[0] = 0;
        dest.cap[1] = 0;
        dest = BPF_CORE_READ(task, cred, cap_permitted);
        ci->cap_permitted = (((u64) dest.cap[1]) << 32) + dest.cap[0];

        dest.cap[0] = 0;
        dest.cap[1] = 0;
        dest = BPF_CORE_READ(task, cred, cap_effective);
        ci->cap_effective = (((u64) dest.cap[1]) << 32) + dest.cap[0];
    } else {
        const struct cred *cred = BPF_CORE_READ(task, cred);
        const void *cap = NULL;

        struct new_kernel_cap_struct {
            u64 val;
        } dest;

        dest.val = 0;
        cap = &cred->cap_permitted;
        bpf_core_read(&dest, sizeof(struct new_kernel_cap_struct), cap);
        ci->cap_permitted = dest.val;

        dest.val = 0;
        cap = &cred->cap_effective;
        bpf_core_read(&dest, sizeof(struct new_kernel_cap_struct), cap);
        ci->cap_effective = dest.val;
    }
}

static long argv__fill(char *buf, size_t buf_size, const struct task_struct *task)
{
    unsigned long start, end, size;

    start = BPF_CORE_READ(task, mm, arg_start);
    end = BPF_CORE_READ(task, mm, arg_end);

    if (end <= start) {
        buf[0] = '\0';
        return 1;
    }

    size = end - start;
    size = size > buf_size ? buf_size : size;

    bpf_probe_read_user(buf, size, (void *) start);

    // Prevent final arg from being unterminated if buf is too small for args
    buf[size - 1] = '\0';

    return size;
}

static long env__fill(char *buf, size_t buf_size, const struct task_struct *task)
{
    unsigned long start, end, size;

    start = BPF_CORE_READ(task, mm, env_start);
    end = BPF_CORE_READ(task, mm, env_end);

    if (end <= start) {
        buf[0] = '\0';
        return 1;
    }

    size = end - start;
    size = size > buf_size ? buf_size : size;

    bpf_probe_read_user(buf, size, (void *) start);

    // Prevent final env from being unterminated if buf is too small for envs
    buf[size - 1] = '\0';

    return size;
}

#endif // __HELPER_H__
