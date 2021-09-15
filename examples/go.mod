module github.com/thanos-community/epbf-instrumentation/examples

go 1.17

require (
	github.com/cloudflare/ebpf_exporter v1.2.4-0.20210906222106-3828623ce797
	github.com/efficientgo/e2e v0.11.2-0.20210910154705-fe343387488b
	github.com/efficientgo/tools/core v0.0.0-20210829154005-c7bad8450208
	github.com/pkg/errors v0.9.1
	gopkg.in/yaml.v3 v3.0.0-20200313102051-9f266ea9e77c

)

require (
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/golang/protobuf v1.4.3 // indirect
	github.com/matttproud/golang_protobuf_extensions v1.0.1 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/prometheus/client_model v0.2.0 // indirect
	github.com/prometheus/common v0.18.0 // indirect
	go.uber.org/goleak v1.1.10 // indirect
	golang.org/x/lint v0.0.0-20190930215403-16217165b5de // indirect
	golang.org/x/tools v0.0.0-20210106214847-113979e3529a // indirect
	google.golang.org/protobuf v1.25.0 // indirect
)

replace (
	github.com/cloudflare/ebpf_exporter => github.com/bwplotka/ebpf_exporter v1.2.4-0.20210915090327-7475bcaac653
	github.com/efficientgo/e2e => github.com/efficientgo/e2e v0.11.2-0.20210910154705-fe343387488b
	github.com/efficientgo/tools/core => github.com/efficientgo/tools/core v0.0.0-20210829154005-c7bad8450208
)
