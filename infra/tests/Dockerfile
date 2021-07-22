ARG TAG=Test_412_find_how_to_unfederate_a_spire_server
FROM cspiffe/workload:${TAG}

RUN apt-get update \
  && apt-get install -y --no-install-recommends software-properties-common python3 python3-pip \
  && apt-get clean

ARG TEST_DIR=/mnt/c-spiffe

WORKDIR ${TEST_DIR}/integration_test

RUN pip3 install -r requirements.txt

# Create user for test workloads
RUN useradd tests -u 1003
RUN useradd client-workload -u 1004
