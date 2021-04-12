FROM ubuntu:focal

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
        wget

RUN apt-get clean

# Install Spire Agent
ARG SPIRE_VERSION=0.12.0
ARG SPIRE_RELEASE=https://github.com/spiffe/spire/releases/download/v${SPIRE_VERSION}/spire-${SPIRE_VERSION}-linux-x86_64-glibc.tar.gz
ARG SPIRE_DIR=/opt/spire

ARG C_SPIFFE_DIR=/mnt/c-spiffe

RUN curl --silent --location $SPIRE_RELEASE | tar -xzf -
RUN mv spire-${SPIRE_VERSION} ${SPIRE_DIR}

RUN ln -s /opt/spire/bin/spire-server /usr/bin/spire-server
RUN ln -s /opt/spire/bin/spire-agent /usr/bin/spire-agent

# Todo: Improve
ARG BRANCH=test/198-Spiffetls-dial+listen-integration-test
RUN cd /mnt && git clone -b ${BRANCH} https://github.com/arianalima/c-spiffe.git
RUN mkdir -p ${C_SPIFFE_DIR}/build/

# Configure Spire
WORKDIR ${SPIRE_DIR}
COPY agent.conf conf/agent/agent.conf
