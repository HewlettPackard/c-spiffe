FROM ubuntu:focal

ENV DEBIAN_FRONTEND noninteractive

RUN ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone

RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential \
        software-properties-common \
        autoconf \
        automake \
        libtool \
        pkg-config \
        ca-certificates \
        git \
        curl \
        tar \
        gzip \
        vim \
        unzip \
        wget \
        cmake \
        libssl-dev

RUN apt-get clean

# Install Spire Agent
ARG SPIRE_VERSION=0.12.0
ARG SPIRE_RELEASE=https://github.com/spiffe/spire/releases/download/v${SPIRE_VERSION}/spire-${SPIRE_VERSION}-linux-x86_64-glibc.tar.gz
ARG SPIRE_DIR=/opt/spire

RUN curl --silent --location $SPIRE_RELEASE | tar -xzf -
RUN mv spire-${SPIRE_VERSION} ${SPIRE_DIR}

RUN ln -s /opt/spire/bin/spire-agent /usr/bin/spire-agent

ARG GRPC_VERSION=1.34.0
ARG NUM_JOBS=8

RUN cd /tmp && git clone --recurse-submodules -b v${GRPC_VERSION} https://github.com/grpc/grpc
RUN mkdir -p /tmp/grpc/cmake/build
RUN cd /tmp/grpc/cmake/build && cmake -DgRPC_INSTALL=ON -DgRPC_SSL_PROVIDER=package -DgRPC_BUILD_TESTS=ON ../../ 
RUN sed -i '7,13d' /tmp/grpc/third_party/benchmark/test/cxx03_test.cc 
RUN cd /tmp/grpc/cmake/build && make -j${NUM_JOBS} && make install

# Configure Spire
WORKDIR ${SPIRE_DIR}
COPY agent.conf conf/agent/agent.conf
