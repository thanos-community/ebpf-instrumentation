// Copyright (c) The EfficientGo Authors.
// Licensed under the Apache License 2.0.

package main

import (
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

	// Create structs for Prometheus containers scraping itself.
	p := e2edb.NewPrometheus(e, "prometheus-1")
	testutil.Ok(t, e2e.StartAndWaitReady(p))

	// To ensure Prometheus scraped already something ensure number of scrapes.
	testutil.Ok(t, p.WaitSumMetrics(e2e.Greater(50), "prometheus_tsdb_head_samples_appended_total"))

	// TODO:
	// * Start epbf exporter
	// * load our program
	// * create application that we want to monitor
	// * create HTTP traffic

	testutil.Ok(t, e2einteractive.OpenInBrowser("http://" + p.Endpoint("http")))
	testutil.Ok(t, e2einteractive.RunUntilEndpointHit())
}
