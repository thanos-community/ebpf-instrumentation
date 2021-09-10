FROM ubuntu:20.04 as builder

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    apt-get -y --no-install-recommends install build-essential pbuilder aptitude git openssh-client ca-certificates

RUN git clone --branch=v0.18.0 --depth=1 https://github.com/iovisor/bcc.git /root/bcc && \
    git -C /root/bcc submodule update --init --recursive

RUN cd /root/bcc && \
    /usr/lib/pbuilder/pbuilder-satisfydepends && \
    PARALLEL=$(nproc) ./scripts/build-deb.sh release

FROM ubuntu:20.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    apt-get install -y --no-install-recommends build-essential software-properties-common git kmod wget

RUN add-apt-repository ppa:longsleep/golang-backports && \
    apt-get install -y --no-install-recommends golang-1.16-go

ENV PATH="/usr/lib/go-1.16/bin:$PATH"

COPY --from=builder /root/bcc/libbcc_*.deb /tmp/libbcc.deb

RUN dpkg -i /tmp/libbcc.deb

RUN git clone --depth=1 https://github.com/cloudflare/ebpf_exporter.git /root/ebpf_exporter && cd /root/ebpf_exporter && git reset --hard 3828623ce797d1d49cb97a95ccf7fbbc4df7c425

RUN cd /root/ebpf_exporter && GOPATH="" GOPROXY="off" GOFLAGS="-mod=vendor" go build -v ./cmd/ebpf_exporter/... && ls -l .

ARG PPA_KERNEL_HEADERS

RUN add-apt-repository $PPA_KERNEL_HEADERS && apt-get install -y --no-install-recommends linux-headers-$(uname -r)

ENTRYPOINT ["/root/ebpf_exporter/ebpf_exporter"]