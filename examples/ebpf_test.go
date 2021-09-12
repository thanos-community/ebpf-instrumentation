// Copyright (c) The EfficientGo Authors.
// Licensed under the Apache License 2.0.

package main

import (
	"fmt"
	"io/ioutil"
	"path/filepath"
	"testing"

	"github.com/cloudflare/ebpf_exporter/config"
	"github.com/efficientgo/e2e"
	e2edb "github.com/efficientgo/e2e/db"
	e2einteractive "github.com/efficientgo/e2e/interactive"
	"github.com/efficientgo/tools/core/pkg/testutil"
	"gopkg.in/yaml.v3"
)

func TestExample(t *testing.T) {
	t.Parallel() // We can run those tests in parallel (as long as host has enough CPU time).

	// Start isolated environment with given ref.
	e, err := e2e.NewDockerEnvironment("e2e_ebpf")
	testutil.Ok(t, err)
	// Make sure resources (e.g docker containers, network, dir) are cleaned.
	t.Cleanup(e.Close)

	// Start epbf exporter.
	exporter := newEBPFExporter(e, eBPFExporterConfig(t))
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

func eBPFExporterConfig(t *testing.T) config.Config {
	return config.Config{
		Programs: []config.Program{
			{
				Name: "ipcstat",
				Metrics: config.Metrics{
					Counters: []config.Counter{
						{
							Name:  "cpu_instructions_total",
							Help:  "Instructions retired by CPUs",
							Table: "instructions",
							Labels: []config.Label{
								{Name: "cpu", Size: 4, Decoders: []config.Decoder{{Name: "uint"}}},
							},
						},
						{
							Name:  "cpu_cycles_total",
							Help:  "Cycles processed by CPUs",
							Table: "cycles",
							Labels: []config.Label{
								{Name: "cpu", Size: 4, Decoders: []config.Decoder{{Name: "uint"}}},
							},
						},
					},
				},
				PerfEvents: []config.PerfEvent{
					{
						Type:            0x0, // HARDWARE
						Name:            0x1, // PERF_COUNT_HW_INSTRUCTIONS
						Target:          "on_cpu_instruction",
						SampleFrequency: 99,
					},
					{
						Type:            0x0, // HARDWARE
						Name:            0x1, // PERF_COUNT_HW_CPU_CYCLES
						Target:          "on_cpu_cycle",
						SampleFrequency: 99,
					},
				},
				Code: func() string {
					b, err := ioutil.ReadFile("../ipcstat.c")
					testutil.Ok(t, err)
					return string(b)
				}(),
			},
		},
	}
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

// newEBPFExporter scheduled new container that is supposed to load our eBPF programs and expose Prometheus metrics from it.
// Similar container could be running as a daemon on Kubernetes cluster.
// Inspired by: https://github.com/ahas-sigs/kube-ebpf-exporter/commit/3d747fbe9941afae0cbb03c21b2c2a02730dd969#diff-8ce071a05afb313c36230f8cd0e51af4986f61dde1bb75efcb38d9e1b867e539.
func newEBPFExporter(e e2e.Environment, config config.Config) e2e.Runnable {
	f := e2e.NewInstrumentedRunnable(e, "ebpf_exporter", map[string]int{"http": 9435}, "http")

	b, err := yaml.Marshal(config)
	if err != nil {
		return e2e.NewErrorer("ebpf_exporter", err)
	}

	if err := ioutil.WriteFile(filepath.Join(f.Dir(), "config.yml"), b, 0600); err != nil {
		return e2e.NewErrorer("ebpf_exporter", err)
	}

	return f.Init(e2e.StartOptions{
		Image:        "ebpf_exporter:v1.2.3-5.11.0-7620-generic", // Unfortunately image is kernel specifc, change it on your machine to make it work.
		Command:      e2e.NewCommand("--config.file", filepath.Join(f.InternalDir(), "config.yml")),
		Privileged:   true,
		Capabilities: []e2e.RunnableCapabilities{e2e.RunnableCapabilitiesSysAdmin},
		Readiness:    e2e.NewHTTPReadinessProbe("http", "/metrics", 200, 200),
	})
}
