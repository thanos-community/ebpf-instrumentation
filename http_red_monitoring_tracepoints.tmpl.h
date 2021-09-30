#include <linux/sched.h>
#include <uapi/linux/ptrace.h>
#include <uapi/linux/stat.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/stat.h>
#include <linux/socket.h>

struct addr_info_t {
  struct sockaddr *addr;
  int *addrlen;
};

BPF_HASH(requests_started_connections_total, u64);
BPF_HASH(requests_closed_connections_total, u64);

struct request_key_t {
      u64 pid;
      char status;
};

BPF_HASH(requests_total, struct request_key_t); // TODO(bwplotka): Parse status path.

// The set of file descriptors we are tracking. In our case those are connections from accept.
// Without this we would increment our metric in any other writes.
BPF_HASH(tracked_fds, u64, struct addr_info_t);

// Tracks struct addr_info so we can map between entry and exit.
// The key is the current pid/tgid.
BPF_HASH(active_sock_addr, u64, struct addr_info_t);

// eBPF stack allows us to only alloc 512 B max. Still 300B is good enough usually to parse response header.
#define MAX_MSG_SIZE 300


// Generates function tracepoint__syscalls__sys_enter_accept4
// args is from /sys/kernel/debug/tracing/events/syscalls/sys_enter_accept4/format
TRACEPOINT_PROBE(syscalls, sys_enter_accept4) {
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id >> 32;
    if (pid != $(PID)) {
        return 0;
    }
    bpf_trace_printk("accept $(PID)!\\n");

   struct addr_info_t addr_info;
   addr_info.addr = args->upeer_sockaddr;
   addr_info.addrlen = args->upeer_addrlen;
   active_sock_addr.update(&id, &addr_info);

    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_accept4) {
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id >> 32;
    if (pid != $(PID)) {
        return 0;
    }

    struct addr_info_t* addr_info = active_sock_addr.lookup(&id);
    if (addr_info == NULL) {
        active_sock_addr.delete(&id);
        return 0;
    }

    // The file descriptor is the value returned from the syscall.
    u64 fd = (u64)args->ret; // Somehow return argument is long type in my kernel.
    if (fd < 0) {
        active_sock_addr.delete(&id);
        return 0;
    }

    tracked_fds.update(&fd, addr_info);
    requests_started_connections_total.increment((u64) pid);

    active_sock_addr.delete(&id);
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_write) {
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id >> 32;
    if (pid != $(PID)) {
        return 0;
    }

    u64 fd = args->fd;
    if (tracked_fds.lookup(&fd) == NULL) {
           return 0;
    }

    // Parse write buf to know if we are sending HTTP headers and with what status code.
    char b[MAX_MSG_SIZE];
     __builtin_memset(&b, 0, sizeof(b));
    size_t buf_size = args->count < sizeof(b) ? args->count : sizeof(b);
    bpf_probe_read(&b, buf_size, (void*) args->buf);
    if ((b[0] == 'H') && (b[1] == 'T') && (b[2] == 'T') && (b[3] == 'P')) {
        bpf_trace_printk("buf: %s\\n", b); // TODO(bwplotka) Get more of buffer and parse status path too!

        struct request_key_t key;
        __builtin_memset(&key, 0, sizeof(key));
        key.pid = (u64) pid;
        key.status = b[9];
        requests_total.increment(key);
    }

   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_close) {
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id >> 32;
    if (pid != $(PID)) {
        return 0;
    }
    u64 fd = args->fd;
    if (tracked_fds.lookup(&fd) == NULL) {
           return 0;
    }
    tracked_fds.delete(&fd);
    requests_closed_connections_total.increment((u64) pid);
    return 0;
}
