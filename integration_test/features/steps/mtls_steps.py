import os
import sys
import time

from hamcrest import assert_that, is_, is_not


# @given('The second agent is turned off')
# def step_impl(context):
#     os.system("pkill spire-agent")
#     time.sleep(5)


@given('The second agent is turned on inside "{container_name}" container')
def step_impl(context, container_name):
    os.system("/mnt/c-spiffe/integration_test/helpers/bash-spire-scripts/ssh-connect_agent.sh %s" % container_name)
    time.sleep(5)
