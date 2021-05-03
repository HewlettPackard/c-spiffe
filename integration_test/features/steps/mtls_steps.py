import os
import sys
import time

from hamcrest import assert_that, is_, is_not


@then('The second agent is turned off inside "{container_name}" container')
def step_impl(context, container_name):
    os.system("/mnt/c-spiffe/integration_test/helpers/bash-spire-scripts/ssh-stop_agent.sh %s" % container_name)
    time.sleep(5)


@given('The second agent is turned on inside "{container_name}" container')
def step_impl(context, container_name):
    os.system("/mnt/c-spiffe/integration_test/helpers/bash-spire-scripts/ssh-connect_agent.sh %s" % container_name)
    time.sleep(5)


@when('The go-tls-listen is activated inside "{container_name}" container')
def step_impl(context, container_name):
    os.system("/mnt/c-spiffe/integration_test/helpers/bash-general-scripts/ssh-run-go-server.sh %s" % container_name)
    time.sleep(1)


@then('The go-tls-listen is disabled inside "{container_name}" container')
def step_impl(context, container_name):
    os.system("/mnt/c-spiffe/integration_test/helpers/bash-general-scripts/ssh-stop-go-server.sh %s" % container_name)
    time.sleep(1)


@when('I send "{message}" through go-tls-dial')
def step_impl(context, message):
    result = os.popen("cd /mnt/c-spiffe/integration_test/helpers/go-echo-server/client && su - client-workload -c './go-client '%s'" % message)
    time.sleep(1)
    context.tls_status = result.read()


@then('I check that "{message}" was the answer from go-tls-listen')
def step_impl(context, message):
    result = context.tls_status.replace("\"","").split("Server replied:")
    actual_message = result[-1].strip().replace("\\n","")
    assert_that(actual_message, is_(message))
