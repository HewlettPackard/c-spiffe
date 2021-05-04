FROM alg4/infra_workload

RUN apt-get update \
  && apt-get install -y --no-install-recommends software-properties-common python3 python3-pip

ARG TEST_DIR=/mnt/c-spiffe

WORKDIR ${TEST_DIR}/integration_test

# failed to build : ADD failed: forbidden path outside the build context:
### ADD ../../integration-test /mnt/tests

RUN pip3 install -r requirements.txt

# Create user for test workloads
RUN useradd tests -u 1003
RUN useradd client-workload -u 1004

# We can added any user for tests but must be sudo
#USER tests
