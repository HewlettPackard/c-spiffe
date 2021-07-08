FROM ubuntu:focal

LABEL maintainer="Willian Alves <wra@cesar.org.br>"

ARG GRPC_VERSION=1.34.0
ARG NUM_JOBS=8

ENV DEBIAN_FRONTEND noninteractive

# Install package dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential \
        apt-transport-https \
        gnupg \
        lsb-release \
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
        zlib1g-dev \
        doxygen \
        graphviz \
        docker-compose \
        libcurl4-openssl-dev\
        golang\
        golang-go;\
pip3 install behave PyHamcrest pathlib2;\
apt-get clean

#install go-spiffe/v2 for tests
RUN go get -u github.com/spiffe/go-spiffe/v2/bundle/spiffebundle && \
go get -u github.com/spiffe/go-spiffe/v2/federation && \
go get -u github.com/spiffe/go-spiffe/v2/logger && \
go get -u github.com/spiffe/go-spiffe/v2/spiffeid && \
go get -u github.com/spiffe/go-spiffe/v2/svid/x509svid

# Install Docker Enginer
RUN curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg
RUN echo \
  "deb [arch=amd64 signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/ubuntu \
  $(lsb_release -cs) stable" | tee /etc/apt/sources.list.d/docker.list > /dev/null ;\
apt-get update && apt-get install -y docker-ce docker-ce-cli containerd.io && apt-get clean

# Install OpenSSL
ARG OPENSSL_VERSION=1.1.1k
ARG OPENSSL_RELEASE=https://www.openssl.org/source/openssl-${OPENSSL_VERSION}.tar.gz
ARG OPENSSL_DIR=/tmp/

RUN cd ${OPENSSL_DIR} ;\
curl --silent --location $OPENSSL_RELEASE | tar -xzf - ;\
mv openssl-${OPENSSL_VERSION} ${OPENSSL_DIR} ;\
cd ${OPENSSL_DIR}openssl-${OPENSSL_VERSION} && ./config --prefix=/usr --openssldir=/usr/lib/ssl --libdir=lib/x86_64-linux-gnu shared -lcrypto && make && make test && make install ;\
rm -rf /tmp/*

RUN cd /tmp && git clone --recurse-submodules -b v${GRPC_VERSION} https://github.com/grpc/grpc ;\
mkdir -p /tmp/grpc/cmake/build ;\
cd /tmp/grpc/cmake/build && cmake -DgRPC_INSTALL=ON -DgRPC_BUILD_TESTS=ON -DgRPC_SSL_PROVIDER=package ../.. ;\
sed -i '7,13d' /tmp/grpc/third_party/benchmark/test/cxx03_test.cc  ;\
cd /tmp/grpc/cmake/build && make -j${NUM_JOBS} && make install ;\
rm -rf /tmp/*

# Install Spire Server
ARG SPIRE_VERSION=0.12.0
ARG SPIRE_RELEASE=https://github.com/spiffe/spire/releases/download/v${SPIRE_VERSION}/spire-${SPIRE_VERSION}-linux-x86_64-glibc.tar.gz
ARG SPIRE_DIR=/opt/spire

RUN curl --silent --location $SPIRE_RELEASE | tar -xzf - ;\
mv spire-${SPIRE_VERSION} ${SPIRE_DIR}

RUN ln -s /opt/spire/bin/spire-server /usr/bin/spire-server
RUN ln -s /opt/spire/bin/spire-agent /usr/bin/spire-agent

RUN rm -rf /tmp/*
