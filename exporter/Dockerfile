FROM ubuntu:20.04 as builder

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    apt-get -y --no-install-recommends install build-essential pbuilder aptitude git openssh-client ca-certificates

RUN git clone --branch=v0.21.0 --depth=1 https://github.com/iovisor/bcc.git /root/bcc && \
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

RUN git clone --branch=exp --depth=1 https://github.com/bwplotka/ebpf_exporter.git /root/ebpf_exporter && cd /root/ebpf_exporter && git reset --hard 06c74bf3500f4a8773c3268b9ce1fe8058ac3b72

RUN cd /root/ebpf_exporter && GOPATH="" GOPROXY="off" GOFLAGS="-mod=vendor" go build -v ./cmd/ebpf_exporter/... && ls -l .

# Make sure to share /lib/modules:/lib/modules:ro volume on start for your linux headers.
ENTRYPOINT ["/root/ebpf_exporter/ebpf_exporter"]