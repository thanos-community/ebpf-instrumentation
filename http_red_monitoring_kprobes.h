#include <linux/sched.h>
#include <uapi/linux/ptrace.h>
#include <uapi/linux/stat.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/stat.h>
#include <linux/socket.h>

BPF_HASH(requests_total, u64);

struct addr_info_t {
  struct sockaddr *addr;
  int *addrlen;
};

#define MAX_MSG_SIZE 1024
BPF_PERF_OUTPUT(syscall_write_events);

// Tracks struct addr_info so we can map between entry and exit.
BPF_HASH(active_sock_addr, u64, struct addr_info_t);
// This function stores the address to the sockaddr struct in the active_sock_addr map.
// The key is the current pid/tgid.

/*
sudo cat /sys/kernel/debug/tracing/events/syscalls/sys_enter_accept4/format
name: sys_enter_accept4
ID: 1434
format:
	field:unsigned short common_type;	offset:0;	size:2;	signed:0;
	field:unsigned char common_flags;	offset:2;	size:1;	signed:0;
	field:unsigned char common_preempt_count;	offset:3;	size:1;	signed:0;
	field:int common_pid;	offset:4;	size:4;	signed:1;

	field:int __syscall_nr;	offset:8;	size:4;	signed:1;
	field:int fd;	offset:16;	size:8;	signed:0;
	field:struct sockaddr * upeer_sockaddr;	offset:24;	size:8;	signed:0;
	field:int * upeer_addrlen;	offset:32;	size:8;	signed:0;
	field:int flags;	offset:40;	size:8;	signed:0;
*/

// syscall__ is a special prefix that creates a kprobe for the system call name provided as the remainder.
int syscall__sys_enter_accept4(struct pt_regs *ctx, int fd, struct sockaddr *addr, int *addrlen, int flags) {
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id >> 32;

 bpf_trace_printk("accept-entry");
  struct addr_info_t addr_info;
  addr_info.addr = addr;
  addr_info.addrlen = addrlen;
  active_sock_addr.update(&id, &addr_info);
  return 0;
}

//// Read the sockaddr values and write to the output buffer.
//int syscall__sys_exit_accept4(struct pt_regs *syscallnum, int fd, struct sockaddr *addr, size_t *addrlen, int flags) {
//  u64 id = bpf_get_current_pid_tgid();
//  u32 pid = id >> 32;
//  bpf_trace_printk("accept");
//  active_sock_addr.delete(&id);
//  return 0;
//}
//
//int syscall__sys_enter_write(struct pt_regs *syscallnum, int fd, const void* buf, size_t count) {
//  bpf_trace_printk("write");
//  return 0;
//}
//
//int syscall__sys_enter_close(struct pt_regs *syscallnum, int fd) {
//  u64 id = bpf_get_current_pid_tgid();
//  u32 pid = id >> 32;
//  bpf_trace_printk("close");
//  return 0;
//}
