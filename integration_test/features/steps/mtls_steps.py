import os
import sys
import time
import subprocess
import socket

from hamcrest import assert_that, is_, is_not
from behave.matchers import register_type
from utils import parse_nullable_string


parse_nullable_string.pattern = r'.*'
register_type(NullableString=parse_nullable_string)


@then('The second agent is turned off inside "{container_name}" container')
def step_impl(context, container_name):
    os.system("/mnt/c-spiffe/integration_test/helpers/bash-spire-scripts/ssh-stop-agent.sh %s" % container_name)
    time.sleep(5)


@given('The second agent is turned on inside "{container_name}" container')
def step_impl(context, container_name):
    os.system("/mnt/c-spiffe/integration_test/helpers/bash-spire-scripts/ssh-connect-agent.sh WlB %s" % container_name)
    time.sleep(5)


@when('The go-tls-listen is activated inside "{container_name}" container')
def step_impl(context, container_name):
    os.system("/mnt/c-spiffe/integration_test/helpers/bash-general-scripts/ssh-run-go-server.sh %s" % container_name)
    time.sleep(1)


@then('The go-tls-listen is disabled inside "{container_name}" container')
def step_impl(context, container_name):
    os.system("/mnt/c-spiffe/integration_test/helpers/bash-general-scripts/ssh-stop-go-server.sh %s" % container_name)
    time.sleep(1)


@when('I send "{message:NullableString}" to "{container_name}" container through "{language}"-tls-dial')
def step_impl(context, message, container_name, language):
    result = ""

    if language == "go":
        client = subprocess.run(["/mnt/c-spiffe/integration_test/helpers/bash-general-scripts/run-go-client.sh '%s'" % message], stderr=subprocess.PIPE, text=True, shell=True)
        time.sleep(1)
        result = client.stderr
    elif language == "c":
        client = os.popen("/mnt/c-spiffe/build/spiffetls/c_dial %s %s" % (message, socket.gethostbyname(container_name)))
        result = client.read()

    actual_message = result.replace("\"","").split("Server replied:")
    context.tls_answer = actual_message[-1].strip().replace("\\n","")


@then('I check that "{message:NullableString}" was the answer from go-tls-listen')
def step_impl(context, message):
    assert_that(context.tls_answer, is_(message))


@given('The second agent is turned on inside "{container_name}" container with different key chain')
def step_impl(context, container_name):
    os.system("/mnt/c-spiffe/integration_test/helpers/bash-spire-scripts/ssh-connect-agent.sh WlC %s" % container_name)
    time.sleep(5)


@given('I set the "{process}" "{field_alias}" to "{new_value}" inside "{container_name}" container')
def step_impl(context, process, field_alias, new_value, container_name):
    if process != ("agent" or "server"):
        raise Exception("Invalid process to update the conf file. Choose 'agent' or 'server'.")
    if field_alias == "port":
        field_name = "bind_port"
    elif field_alias == "trust domain":
        field_name = "trust_domain"
    else:
        raise Exception("Invalid field to update in the server.conf/agent.conf file.")
    os.system("/mnt/c-spiffe/integration_test/helpers/bash-spire-scripts/ssh-update-server-conf.sh %s %s %s %s" % (field_name, new_value, process, container_name))


@given('The second server is turned on inside "{container_name}" container')
def step_impl(context, container_name):
    os.system("/mnt/c-spiffe/integration_test/helpers/bash-spire-scripts/ssh-start-server.sh %s" % container_name)
    time.sleep(5)
    os.system("/mnt/c-spiffe/integration_test/helpers/bash-spire-scripts/ssh-create-entries.sh %s" % container_name)
