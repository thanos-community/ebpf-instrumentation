// Copyright (c) The EfficientGo Authors.
// Licensed under the Apache License 2.0.

package main

import (
	"fmt"
	"io/ioutil"
	"path/filepath"
	"testing"

	"github.com/efficientgo/e2e"
	e2edb "github.com/efficientgo/e2e/db"
	e2einteractive "github.com/efficientgo/e2e/interactive"
	"github.com/efficientgo/tools/core/pkg/testutil"
)

func TestExample(t *testing.T) {
	t.Parallel() // We can run those tests in parallel (as long as host has enough CPU time).

	// Start isolated environment with given ref.
	e, err := e2e.NewDockerEnvironment("e2e_ebpf")
	testutil.Ok(t, err)
	// Make sure resources (e.g docker containers, network, dir) are cleaned.
	t.Cleanup(e.Close)

	// Start epbf exporter.
	exporter := newEBPFExporter(e, ebpCPUMonitoring)
	testutil.Ok(t, e2e.StartAndWaitReady(exporter))

	// Create structs for Prometheus containers scraping itself.
	// We will use eBPF to monitor prometheus itself.
	p := e2edb.NewPrometheus(e, "prometheus")
	testutil.Ok(t, e2e.StartAndWaitReady(p))
	testutil.Ok(t, injectPrometheusConfig(p, exporter))

	// To ensure Prometheus scraped already something ensure number of scrapes.
	testutil.Ok(t, p.WaitSumMetrics(e2e.Greater(50), "prometheus_tsdb_head_samples_appended_total"))

	testutil.Ok(t, e2einteractive.OpenInBrowser("http://"+p.Endpoint("http")))
	testutil.Ok(t, e2einteractive.RunUntilEndpointHit())
}

func injectPrometheusConfig(p *e2edb.Prometheus, exporter e2e.Runnable) error {
	return p.SetConfig(fmt.Sprintf(`
global:
  external_labels:
    prometheus: "prometheus"
scrape_configs:
- job_name: 'myself'
  # Quick scrapes for test purposes.
  scrape_interval: 1s
  scrape_timeout: 1s
  static_configs:
  - targets: [%s]
  relabel_configs:
  - source_labels: ['__address__']
    regex: '^.+:80$'
    action: drop
- job_name: 'ebpf_exporter'
  # Quick scrapes for test purposes.
  scrape_interval: 1s
  scrape_timeout: 1s
  static_configs:
  - targets: [%s]
`, p.InternalEndpoint("http"), exporter.InternalEndpoint("http")))
}

const ebpCPUMonitoring = `programs:
  # See:
  # * http://www.brendangregg.com/blog/2017-05-09/cpu-utilization-is-wrong.html
  - name: ipcstat
    metrics:
      counters:
        - name: cpu_instructions_total
          help: Instructions retired by CPUs
          table: instructions
          labels:
            - name: cpu
              size: 4
              decoders:
                - name: uint
        - name: cpu_cycles_total
          help: Cycles processed by CPUs
          table: cycles
          labels:
            - name: cpu
              size: 4
              decoders:
                - name: uint
    perf_events:
      - type: 0x0 # HARDWARE
        name: 0x1 # PERF_COUNT_HW_INSTRUCTIONS
        target: on_cpu_instruction
        sample_frequency: 99
      - type: 0x0 # HARDWARE
        name: 0x0 # PERF_COUNT_HW_CPU_CYCLES
        target: on_cpu_cycle
        sample_frequency: 99
    code: |
      #include <linux/ptrace.h>
      #include <uapi/linux/bpf_perf_event.h>
      const int max_cpus = 128;
      BPF_ARRAY(instructions, u64, max_cpus);
      BPF_ARRAY(cycles, u64, max_cpus);
      int on_cpu_instruction(struct bpf_perf_event_data *ctx) {
          instructions.increment(bpf_get_smp_processor_id(), ctx->sample_period);
          return 0;
      }
      int on_cpu_cycle(struct bpf_perf_event_data *ctx) {
          cycles.increment(bpf_get_smp_processor_id(), ctx->sample_period);
          return 0;
      }
`

// newEBPFExporter scheduled new container that is supposed to load our eBPF programs and expose Prometheus metrics from it.
// Similar container could be running as a daemon on Kubernetes cluster.
// Inspired by: https://github.com/ahas-sigs/kube-ebpf-exporter/commit/3d747fbe9941afae0cbb03c21b2c2a02730dd969#diff-8ce071a05afb313c36230f8cd0e51af4986f61dde1bb75efcb38d9e1b867e539.
func newEBPFExporter(e e2e.Environment, config string) e2e.Runnable {
	f := e2e.NewInstrumentedRunnable(e, "ebpf_exporter", map[string]int{"http": 9435}, "http")
	if err := ioutil.WriteFile(filepath.Join(f.Dir(), "config.yml"), []byte(config), 0600); err != nil {
		return e2e.NewErrorer("ebpf_exporter", err)
	}

	return f.Init(e2e.StartOptions{
		Image:        "ebpf_exporter:v1.2.3",
		Command:      e2e.NewCommand("--config.file", filepath.Join(f.InternalDir(), "config.yml")),
		Privileged:   true,
		Capabilities: []e2e.RunnableCapabilities{e2e.RunnableCapabilitiesSysAdmin},
		Readiness:    e2e.NewHTTPReadinessProbe("http", "/metrics", 200, 200),
	})
}
