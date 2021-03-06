// Copyright (c) The EfficientGo Authors.
// Licensed under the Apache License 2.0.

package main

import (
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cloudflare/ebpf_exporter/config"
	"github.com/efficientgo/e2e"
	e2edb "github.com/efficientgo/e2e/db"
	e2einteractive "github.com/efficientgo/e2e/interactive"
	"github.com/efficientgo/tools/core/pkg/errcapture"
	"github.com/efficientgo/tools/core/pkg/testutil"
	"github.com/pkg/errors"
	"gopkg.in/yaml.v3"
)

func TestExample(t *testing.T) {
	t.Parallel() // We can run those tests in parallel (as long as host has enough CPU time).

	// Start isolated environment with given ref.
	e, err := e2e.NewDockerEnvironment("e2e_ebpf")
	testutil.Ok(t, err)
	// Make sure resources (e.g docker containers, network, dir) are cleaned.
	t.Cleanup(e.Close)

	// Create structs for Prometheus containers scraping itself.
	// We will use eBPF to monitor prometheus itself.
	p := e2edb.NewPrometheus(e, "prometheus")
	testutil.Ok(t, e2e.StartAndWaitReady(p))

	// Hacky.
	out, err := exec.Command("docker", "inspect", "-f", "'{{.State.Pid}}'", "e2e_ebpf-"+p.Name()).Output()
	testutil.Ok(t, err, string(out))

	// Start epbf exporter.
	exporter := newEBPFExporter(e, eBPFExporterConfig(t, strings.ReplaceAll(strings.ReplaceAll(string(out), "\n", ""), "'", "")))
	testutil.Ok(t, e2e.StartAndWaitReady(exporter))

	testutil.Ok(t, injectPrometheusConfig(p, exporter))

	// To ensure Prometheus scraped already something ensure number of scrapes.
	testutil.Ok(t, p.WaitSumMetrics(e2e.Greater(50), "prometheus_tsdb_head_samples_appended_total"))

	// Demo step 1.
	testutil.Ok(t, e2einteractive.OpenInBrowser("http://"+p.Endpoint("http")+"/graph?g0.expr=sum(prometheus_http_requests_total%7B%7D)%20by%20(code)&g0.tab=0&g0.stacked=0&g0.range_input=15m&g1.expr=ebpf_exporter_http_requests_total&g1.tab=0&g1.stacked=0&g1.range_input=15m&g2.expr=ebpf_exporter_requests_started_connections_total&g2.tab=0&g2.stacked=0&g2.range_input=15m&g3.expr=ebpf_exporter_requests_closed_connections_total&g3.tab=0&g3.stacked=0&g3.range_input=15m"))
	testutil.Ok(t, e2einteractive.RunUntilEndpointHit())

	// Step 2.
	testutil.Ok(t, e2einteractive.OpenInBrowser("http://"+p.Endpoint("http")+"/api/v1/query")) // No params, should give 400.
	testutil.Ok(t, e2einteractive.RunUntilEndpointHit())

	// Step 3.
	testutil.Ok(t, e2einteractive.OpenInBrowser("http://"+p.Endpoint("http")+"/graphsdfsdf")) // Not found, should give 400.
	testutil.Ok(t, e2einteractive.RunUntilEndpointHit())
}

func eBPFExporterConfig(t *testing.T, pidToMonitor string) config.Config {
	return config.Config{
		Programs: []config.Program{
			{
				Name: "http_red_monitoring_tracepoints",
				Metrics: config.Metrics{
					Aggregation: "sum",
					Counters: []config.Counter{
						{
							Name:  "requests_started_connections_total",
							Help:  "Total number of network connections started by container",
							Table: "requests_started_connections_total",
							Labels: []config.Label{
								{Name: "containerID", Size: 8, Decoders: []config.Decoder{
									{Name: "uint"},
									{Name: "docker_containerid_from_pid"},
								}},
							},
						},
						{
							Name:  "requests_closed_connections_total",
							Help:  "Total number of network connections closed by container",
							Table: "requests_closed_connections_total",
							Labels: []config.Label{
								{Name: "containerID", Size: 8, Decoders: []config.Decoder{
									{Name: "uint"},
									{Name: "docker_containerid_from_pid"},
								}},
							},
						},
						{
							Name:  "http_requests_total",
							Help:  "Total number of HTTP requests handled by container",
							Table: "requests_total",
							Labels: []config.Label{
								{Name: "containerID", Size: 8, Decoders: []config.Decoder{
									{Name: "uint"},
									{Name: "docker_containerid_from_pid"},
								}},
								{Name: "code", Size: 8, Decoders: []config.Decoder{
									{Name: "string"},
								}},
							},
						},
					},
				},
				Tracepoints: map[string]string{
					"syscalls:sys_enter_accept4": "tracepoint__syscalls__sys_enter_accept4",
					"syscalls:sys_exit_accept4":  "tracepoint__syscalls__sys_exit_accept4",
					"syscalls:sys_enter_write":   "tracepoint__syscalls__sys_enter_write",
					"syscalls:sys_enter_close":   "tracepoint__syscalls__sys_enter_close",
				},

				Code: func() string {
					b, err := ioutil.ReadFile("../http_red_monitoring_tracepoints.tmpl.h")
					testutil.Ok(t, err)
					return strings.ReplaceAll(string(b), "$(PID)", pidToMonitor)
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
  scrape_interval: 5s
  scrape_timeout: 5s
  static_configs:
  - targets: [%s]
  relabel_configs:
  - source_labels: ['__address__']
    regex: '^.+:80$'
    action: drop
- job_name: 'ebpf_exporter'
  # Quick scrapes for test purposes.
  scrape_interval: 5s
  scrape_timeout: 5s
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
		Image:        "ebpf_exporter:v1.2.3-ubuntu-generic", // Unfortunately image is OS specific, change it on your machine to make it work.
		Command:      e2e.NewCommand("--config.file", filepath.Join(f.InternalDir(), "config.yml")),
		Privileged:   true,
		Capabilities: []e2e.RunnableCapabilities{e2e.RunnableCapabilitiesSysAdmin},
		Readiness:    e2e.NewHTTPReadinessProbe("http", "/metrics", 200, 200),
		Volumes: []string{
			"/lib/modules:/lib/modules:ro",        // This takes your own headers, make sure you install them using `apt-get install linux-headers-$(uname -r)` on ubuntu.
			"/sys/kernel/debug:/sys/kernel/debug", // Required for tracepoints to work.
			"/proc/:/proc",                        // This is required for docker_containerid_from_pid decoder to work (scary).
		},
	})
}

func copyDirs(src, dst string) (err error) {
	fds, err := os.ReadDir(src)
	if err != nil {
		return errors.Wrap(err, "read dir")
	}
	for _, fd := range fds {
		if fd.IsDir() {
			if err := copyDirs(filepath.Join(src, fd.Name()), filepath.Join(dst, fd.Name())); err != nil {
				return errors.Wrap(err, "copy dir")
			}
			continue
		}
		if err := copyFiles(filepath.Join(src, fd.Name()), filepath.Join(dst, fd.Name())); err != nil {
			return errors.Wrap(err, "copy files")
		}
	}
	return nil
}

func copyFiles(src, dst string) (err error) {
	sourceFileStat, err := os.Stat(src)
	if err != nil {
		return errors.Wrap(err, "cpy source")
	}

	if !sourceFileStat.Mode().IsRegular() {
		return errors.Errorf("%s is not a regular file", src)
	}

	source, err := os.Open(src)
	if err != nil {
		return errors.Wrap(err, "cpy source")
	}
	defer errcapture.ExhaustClose(&err, source, "src close")

	if err := os.MkdirAll(filepath.Dir(dst), os.ModePerm); err != nil {
		return err
	}

	destination, err := os.Create(dst)
	if err != nil {
		return errors.Wrap(err, "cpy dest")
	}
	defer errcapture.ExhaustClose(&err, destination, "dst close")

	_, err = io.Copy(destination, source)
	return err
}
