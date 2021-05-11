FROM alg4/infra_spire-agent

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

ARG BRANCH=test/198-implement-test-cases
RUN cd /mnt && git clone -b ${BRANCH} https://github.com/arianalima/c-spiffe.git
RUN cd ${C_SPIFFE_DIR} && git pull
RUN mkdir -p ${C_SPIFFE_DIR}/build/
RUN chmod +x -R ${C_SPIFFE_DIR}/integration_test
RUN chmod +x -R ${C_SPIFFE_DIR}/infra

WORKDIR ${C_SPIFFE_DIR}/build
COPY build-tests-workload.sh .

RUN useradd server-workload
