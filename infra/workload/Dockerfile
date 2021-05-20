FROM cspiffe/spire-agent

ARG C_SPIFFE_DIR=/mnt/c-spiffe

ENV DEBIAN_FRONTEND noninteractive

# Install package dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
        gdb \
        cmake \
        libssl-dev \
        liburiparser1 liburiparser-dev \
        protobuf-compiler \
        libprotobuf-dev \
        check \
        lcov \
        gcovr \
	libjansson-dev \
        libcjose-dev \
        libgtest-dev \
        libgmock-dev \
        golang-go \
        openssh-server
RUN apt-get clean

RUN mkdir -p ${C_SPIFFE_DIR}/build/
RUN cd ${C_SPIFFE_DIR}/build/ && rm -rf

RUN chmod +x -R ${C_SPIFFE_DIR}/integration_test
RUN chmod +x -R ${C_SPIFFE_DIR}/infra

WORKDIR ${C_SPIFFE_DIR}/build

RUN useradd server-workload
