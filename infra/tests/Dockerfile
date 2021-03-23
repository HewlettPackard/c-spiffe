FROM infra_workload

RUN apt-get update \
  && apt-get install -y --no-install-recommends software-properties-common python3 python3-pip

ARG TEST_DIR=/mnt/c-spiffe

WORKDIR ${TEST_DIR}/integration_test

# failed to build : ADD failed: forbidden path outside the build context:
### ADD ../../integration-test /mnt/tests

RUN pip3 install -r requirements.txt

COPY get-entries.sh .
COPY get-entries.py .
COPY run-behave-tests.sh .

RUN chmod +x get-entries.sh
RUN chmod +x get-entries.py
RUN chmod +x run-behave-tests.sh

# Create user for test workloads
RUN useradd tests -u 1002

# We can added any user for tests but must be sudo
#USER tests
