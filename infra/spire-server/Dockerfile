FROM ubuntu:focal

RUN apt-get update \
  && apt-get install -y --no-install-recommends ca-certificates curl tar gzip

# Install Spire Server
ARG SPIRE_VERSION=0.12.0
ARG SPIRE_RELEASE=https://github.com/spiffe/spire/releases/download/v${SPIRE_VERSION}/spire-${SPIRE_VERSION}-linux-x86_64-glibc.tar.gz
ARG SPIRE_DIR=/opt/spire

RUN curl --silent --location $SPIRE_RELEASE | tar -xzf -
RUN mv spire-${SPIRE_VERSION} ${SPIRE_DIR}

# Configure Spire
WORKDIR ${SPIRE_DIR}
COPY server.conf conf/server/server.conf
COPY init-server.sh .
COPY create-entries.sh .
RUN chmod +x init-server.sh
RUN chmod +x create-entries.sh

