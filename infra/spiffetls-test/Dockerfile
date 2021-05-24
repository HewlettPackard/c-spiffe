FROM willallves/grpc-build:1.34.0

RUN apt-get update \
  && apt-get install -y --no-install-recommends software-properties-common python3 python3-pip

ARG TEST_DIR=/mnt/c-spiffe

WORKDIR /opt/spire

# Create user {client-workload, server-workload} for test 
RUN useradd client-workload
RUN useradd server-workload

# Copy go binary file for tests
COPY client /home
COPY server /home

RUN chmod +x /opt/spire/connect_agent.sh
RUN chmod +x /opt/spire/generate_token.sh

# We can added any user for tests but must be sudo
#USER tests
