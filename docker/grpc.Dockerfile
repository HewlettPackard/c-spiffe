FROM ubuntu:focal

LABEL maintainer="Willian Alves <wra@cesar.org.br>"

ARG GRPC_VERSION=1.34.0
ARG NUM_JOBS=8

ENV DEBIAN_FRONTEND noninteractive

# Install package dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential \
        software-properties-common \
        autoconf \
        automake \
        libtool \
        pkg-config \
        ca-certificates \
        wget \
        git \
        curl \
        tar \
        gzip \
        vim \
        gdb \
        valgrind \
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
        python3-pip \
        checkinstall \
        zlib1g-dev
RUN pip3 install behave PyHamcrest pathlib2
RUN apt-get clean

# gRPC
# https://github.com/grpc/grpc/tree/master/src/cpp
# https://github.com/grpc/grpc/blob/master/BUILDING.md

# RUN apt-get install -y build-essential autoconf libtool pkg-config && \
RUN cd /tmp && git clone --recurse-submodules -b v${GRPC_VERSION} https://github.com/grpc/grpc
RUN mkdir -p /tmp/grpc/cmake/build
RUN cd /tmp/grpc/cmake/build && cmake -DgRPC_INSTALL=ON -DgRPC_BUILD_TESTS=ON ../..
RUN sed -i '7,13d' /tmp/grpc/third_party/benchmark/test/cxx03_test.cc 
RUN cd /tmp/grpc/cmake/build && make -j${NUM_JOBS} && make install

# Install Spire Server
ARG SPIRE_VERSION=0.12.0
ARG SPIRE_RELEASE=https://github.com/spiffe/spire/releases/download/v${SPIRE_VERSION}/spire-${SPIRE_VERSION}-linux-x86_64-glibc.tar.gz
ARG SPIRE_DIR=/opt/spire

RUN curl --silent --location $SPIRE_RELEASE | tar -xzf -
RUN mv spire-${SPIRE_VERSION} ${SPIRE_DIR}

RUN ln -s /opt/spire/bin/spire-server /usr/bin/spire-server
RUN ln -s /opt/spire/bin/spire-agent /usr/bin/spire-agent

# Install OpenSSL
ARG OPENSSL_VERSION=1.1.1k
ARG OPENSSL_RELEASE=https://www.openssl.org/source/openssl-${OPENSSL_VERSION}.tar.gz
ARG OPENSSL_DIR=/opt/


RUN mv /usr/bin/openssl /usr/bin/openssl.old
RUN curl --silent --location $OPENSSL_RELEASE | tar -xzf -
RUN mv openssl-${OPENSSL_VERSION} ${OPENSSL_DIR}
RUN cd /opt/openssl-${OPENSSL_VERSION} && ./config --prefix=/usr/local/ssl --openssldir=/usr/local/ssl shared -lcrypto && make && make test && make install
RUN touch /etc/ld.so.conf.d/openssl-${OPENSSL_VERSION}.conf && echo "/usr/local/ssl/lib" >> /etc/ld.so.conf.d/openssl-${OPENSSL_VERSION}.conf
RUN ln -s /usr/local/ssl/bin/openssl /usr/bin/openssl
RUN ldconfig -v
