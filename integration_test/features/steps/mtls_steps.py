import os
import sys
import time

from hamcrest import assert_that, is_, is_not


@given('I access the "{container_name}" container')
def step_impl(context, container_name):
    os.system("/mnt/c-spiffe/integration_test/helpers/bash-general-scripts/ssh-access.sh infra_%s_1" % container_name)


# @given('The second agent is turned off')
# def step_impl(context):
#     os.system("pkill spire-agent")
#     time.sleep(5)


# @given('The second agent is turned on')
# def step_impl(context):
#     os.system("/mnt/c-spiffe/integration_test/helpers/bash-spire-scripts/grpc_connect_agent.sh")
#     time.sleep(5)
