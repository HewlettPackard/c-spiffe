FROM ubuntu:focal

RUN apt-get update \
  && apt-get install -y --no-install-recommends ca-certificates git curl tar gzip vim unzip wget

# Install Spire Agent
ARG SPIRE_VERSION=0.12.0
ARG SPIRE_RELEASE=https://github.com/spiffe/spire/releases/download/v${SPIRE_VERSION}/spire-${SPIRE_VERSION}-linux-x86_64-glibc.tar.gz
ARG SPIRE_DIR=/opt/spire

ARG C_SPIFFE_DIR=/mnt/c-spiffe
ARG BRANCH=create_infra

RUN curl --silent --location $SPIRE_RELEASE | tar -xzf -
RUN mv spire-${SPIRE_VERSION} ${SPIRE_DIR}

RUN cd /mnt && git clone -b ${BRANCH} https://github.com/willallves/c-spiffe.git
RUN mkdir -p ${C_SPIFFE_DIR}/build/

# Configure Spire
WORKDIR ${SPIRE_DIR}
COPY agent.conf conf/agent/agent.conf
