#include <linux/ptrace.h>
#include <uapi/linux/bpf_perf_event.h>

const int max_cpus = 128;

BPF_ARRAY(instructions, u64, max_cpus);
BPF_ARRAY(cycles, u64, max_cpus);
int on_cpu_instruction(struct bpf_perf_event_data *ctx) {
  bpf_trace_printk("yolo"); // This prints to  /sys/kernel/debug/tracing/trace_pipe
  instructions.increment(bpf_get_smp_processor_id(), ctx->sample_period);
  return 0;
}

int on_cpu_cycle(struct bpf_perf_event_data *ctx) {
  bpf_trace_printk("yolo"); // This prints to  /sys/kernel/debug/tracing/trace_pipe
  cycles.increment(bpf_get_smp_processor_id(), ctx->sample_period);
  return 0;
}