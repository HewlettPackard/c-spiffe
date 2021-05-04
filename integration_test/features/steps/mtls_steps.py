import os
import sys
import time
import subprocess

from hamcrest import assert_that, is_, is_not
from behave.matchers import register_type
from utils import parse_nullable_string


parse_nullable_string.pattern = r'.*'
register_type(NullableString=parse_nullable_string)


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


@when('I send "{message:NullableString}" through go-tls-dial')
def step_impl(context, message):
    client = subprocess.run(["/mnt/c-spiffe/integration_test/helpers/bash-general-scripts/run-go-client.sh '%s'" % message], stderr=subprocess.PIPE, text=True, shell=True)
    time.sleep(1)
    result = client.stderr.replace("\"","").split("Server replied:")
    context.tls_answer = result[-1].strip().replace("\\n","")


@then('I check that "{message:NullableString}" was the answer from go-tls-listen')
def step_impl(context, message):
    actual_message = context.tls_answer
    assert_that(actual_message, is_(message))
