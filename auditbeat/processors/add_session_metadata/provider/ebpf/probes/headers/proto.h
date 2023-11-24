// SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause

/*
 * Copyright (C) 2022 Elasticsearch BV
 *
 * This software is dual-licensed under the BSD 2-Clause and GPL v2 licenses.
 * You may choose either one of them if you use this software.
 */

#ifndef __PROTO_H__
#define __PROTO_H__

#define TASK_COMM_LEN 16

enum event_type {
    EVENT_PROCESS_FORK = 0,
    EVENT_PROCESS_EXEC = 1,
    EVENT_PROCESS_EXIT = 2,
    EVENT_PROCESS_SETSID = 3,

    EVENT_FILE_CREATE_EXECUTABLE = 4,
    EVENT_FILE_MODIFY_EXECUTABLE = 5,
    EVENT_FILE_CREATE_FILE = 6,
    EVENT_FILE_MODIFY_FILE = 7,
    EVENT_FILE_DELETE_FILE = 8
};

enum hook_point {
    TRACEPOINT__SCHED_PROCESS_FORK = 0,
    TRACEPOINT__SCHED_PROCESS_EXEC = 1,
    TRACEPOINT__SYSCALLS_SYS_EXIT_SETSID = 2,
    KPROBE__TASKSTATS_EXIT = 3,

    LSM__PATH_CHMOD = 4,
    LSM__PATH_MKNOD = 5,
    LSM__FILE_OPEN = 6,
    LSM__PATH_TRUNCATE = 7,
    LSM__PATH_RENAME = 8,
    LSM__PATH_LINK = 9,
    LSM__PATH_UNLINK = 10,
    LSM__TASK_ALLOC = 11,
    LSM__BPRM_CHECK = 12,
};

struct event_hdr {
    uint64_t type;
    uint64_t ts;
    uint64_t hook_point;
} __attribute__((packed));

// Some fields passed up (e.g. argv, path names) have a high maximum size but
// most instances of them won't come close to hitting the maximum. Instead of
// wasting a huge amount of memory by using a fixed-size buffer that's the
// maximum possible size, we pack these fields into variable-length buffers at
// the end of each event. If a new field to be added has a large maximum size
// that won't often be reached, it should be added as a variable length field.
enum varlen_field_type {
    VL_FIELD_CWD = 1,
    VL_FIELD_ARGV = 2,
    VL_FIELD_ENV = 3,
    VL_FIELD_FILENAME = 4,
    VL_FIELD_PIDS_SS_CGROUP_PATH = 5,
};

struct varlen_fields_start {
    uint32_t nfields;
    uint64_t size;
    char data[];
} __attribute__((packed));

struct varlen_field {
    uint32_t type;
    uint32_t size;
    char data[];
} __attribute__((packed));

struct pid_info {
    uint64_t start_time_ns;
    uint32_t tid;
    uint32_t tgid;
    uint32_t vpid;
    uint32_t ppid;
    uint32_t pgid;
    uint32_t sid;
} __attribute__((packed));

struct cred_info {
    uint32_t ruid; // Real user ID
    uint32_t rgid; // Real group ID
    uint32_t euid; // Effective user ID
    uint32_t egid; // Effective group ID
    uint32_t suid; // Saved user ID
    uint32_t sgid; // Saved group ID
    uint64_t cap_permitted;
    uint64_t cap_effective;
} __attribute__((packed));

struct tty_winsize {
    uint16_t rows;
    uint16_t cols;
} __attribute__((packed));

struct tty_termios {
    uint32_t c_iflag;
    uint32_t c_oflag;
    uint32_t c_lflag;
    uint32_t c_cflag;
} __attribute__((packed));

struct tty_dev {
    uint16_t minor;
    uint16_t major;
    struct tty_winsize winsize;
    struct tty_termios termios;
} __attribute__((packed));

// Full events follow
struct process_fork_event {
    struct event_hdr hdr;
    struct pid_info parent_pids;
    struct pid_info child_pids;
    struct cred_info creds;

    // Variable length fields: pids_ss_cgroup_path
    struct varlen_fields_start vl_fields;
} __attribute__((packed));

struct process_exec_event {
    struct event_hdr hdr;
    struct pid_info pids;
    struct cred_info creds;
    struct tty_dev ctty;

    // Variable length fields: cwd, argv, env, filename, pids_ss_cgroup_path
    struct varlen_fields_start vl_fields;
} __attribute__((packed));

struct process_exit_event {
    struct event_hdr hdr;
    struct pid_info pids;
    int32_t exit_code;

    // Variable length fields: pids_ss_cgroup_path
    struct varlen_fields_start vl_fields;
} __attribute__((packed));

struct process_setsid_event {
    struct event_hdr hdr;
    struct pid_info pids;

    // Variable length fields: pids_ss_cgroup_path
    struct varlen_fields_start vl_fields;
} __attribute__((packed));

struct file_create_executable_event {
    struct event_hdr hdr;
    struct pid_info pids;

    // Variable length fields: filename, pids_ss_cgroup_path
    struct varlen_fields_start vl_fields;
} __attribute__((packed));

struct file_modify_executable_event {
    struct event_hdr hdr;
    struct pid_info pids;

    // Variable length fields: filename, pids_ss_cgroup_path
    struct varlen_fields_start vl_fields;
} __attribute__((packed));

struct file_create_file_event {
    struct event_hdr hdr;
    struct pid_info pids;

    // Variable length fields: filename, pids_ss_cgroup_path
    struct varlen_fields_start vl_fields;
} __attribute__((packed));

struct file_modify_file_event {
    struct event_hdr hdr;
    struct pid_info pids;

    // Variable length fields: filename, pids_ss_cgroup_path
    struct varlen_fields_start vl_fields;
} __attribute__((packed));

struct file_delete_file_event {
    struct event_hdr hdr;
    struct pid_info pids;

    // Variable length fields: filename, pids_ss_cgroup_path
    struct varlen_fields_start vl_fields;
} __attribute__((packed));

#endif // __PROTO_H__
