import os
import sys
import time

from hamcrest import assert_that, is_, is_not


@given('The second agent is turned off inside "{container_name}" container')
def step_impl(context, container_name):
    os.system('ssh root@%s << "EOL" pkill spire-agent EOL' % container_name)
    time.sleep(5)


@given('The second agent is turned on inside "{container_name}" container')
def step_impl(context, container_name):
    os.system("/mnt/c-spiffe/integration_test/helpers/bash-spire-scripts/ssh-connect_agent.sh %s" % container_name)
    time.sleep(5)


# @when('I fetch external "{profile}" "{document}"')
# def step_impl(context, profile, document):
#     if document == "SVID":
#         bin_file = "c_client"
#     else:
#         bin_file = "c_client_bundle"

#     c_client_bin = os.popen("/mnt/c-spiffe/build/workload/%s %s_type=%s" % (bin_file, document.lower(), profile.lower()))
#     context.result = c_client_bin.read()