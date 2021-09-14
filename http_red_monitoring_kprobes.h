#include <linux/sched.h>
#include <uapi/linux/ptrace.h>
#include <uapi/linux/stat.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/stat.h>
#include <linux/socket.h>

BPF_HASH(requests_started_total, u64);
BPF_HASH(requests_total, u64); // TODO(bwplotka): Add status code, and path.

struct addr_info_t {
  struct sockaddr *addr;
  int *addrlen;
};

// The set of file descriptors we are tracking. In our case those are connections from accept.
BPF_HASH(tracked_fds, u64, bool);

// Tracks struct addr_info so we can map between entry and exit.
// The key is the current pid/tgid.
BPF_HASH(active_sock_addr, u64, struct addr_info_t);

// Generates function tracepoint__syscalls__sys_enter_accept4
// args is from /sys/kernel/debug/tracing/events/syscalls/sys_enter_accept4/format
TRACEPOINT_PROBE(syscalls, sys_enter_accept4) {
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id >> 32;

//   struct addr_info_t addr_info;
//   addr_info.addr = args->upeer_sockaddr;
//   addr_info.addrlen = args->upeer_addrlen;
//   active_sock_addr.update(&id, &addr_info);

    // bpf_trace_printk("accept %d\\n", bpf_get_current_cgroup_id());
    return 0;
}


// Read the sockaddr values and write to the output buffer.
TRACEPOINT_PROBE(syscalls, sys_exit_accept4) {
    // The file descriptor is the value returned from the syscall.
    u64 fd = (u64)args->ret; // Somehow return argument is long type in my kernel.
        if (fd < 0) {
            return 0;
        }

        bool t = true;
        tracked_fds.update(&fd, &t);

        requests_started_total.increment((u64) bpf_get_current_cgroup_id());

//  u64 id = bpf_get_current_pid_tgid();
//  u32 pid = id >> 32;
//  bpf_trace_printk("accept");
//  active_sock_addr.delete(&id);
  return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_write) {
    u64 fd = args->fd;
    if (tracked_fds.lookup(&fd) == NULL) {
        return 0;
    }
    // bpf_trace_printk("write");
    requests_total.increment((u64) bpf_get_current_cgroup_id());
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_close) {
    //    tracked_fds.delete(&(args->fd));

    //bpf_trace_printk("close");
    return 0;
}
