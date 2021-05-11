FROM willallves/grpc-build:1.34.0

RUN apt-get update \
  && apt-get install -y --no-install-recommends software-properties-common python3 python3-pip

ARG TEST_DIR=/mnt/c-spiffe

WORKDIR ${TEST_DIR}/integration_test

RUN pip3 install -r requirements.txt

# Create user for test workloads
RUN useradd tests -u 1002
RUN useradd client-workload -u 1003

ARG C_SPIFFE_DIR=/mnt/c-spiffe
RUN mkdir -p ${C_SPIFFE_DIR}

COPY . ${C_SPIFFE_DIR}/

# We can added any user for tests but must be sudo
#USER tests
