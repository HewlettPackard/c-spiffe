import os
import time
import subprocess
import socket

from hamcrest import assert_that, is_, is_not
from behave.matchers import register_type
from utils import parse_nullable_string, is_entry_created, remove_entry


parse_nullable_string.pattern = r'.*'
register_type(NullableString=parse_nullable_string)


@step('The second "{process}" is turned off inside "{container_name}" container')
def step_impl(context, process, container_name):
    if process != "agent" and process != "server":
        raise Exception("Invalid process '%s'. Choose 'agent' or 'server'." % process)
    workload_id = ""
    if context.workload_b in context.tags:
        workload_id = context.workload_b
    elif context.workload_c in context.tags:
        workload_id = context.workload_c
    os.system("/mnt/c-spiffe/integration_test/helpers/bash-spire-scripts/ssh-stop-process.sh %s %s" % (process, container_name))


@step('The second agent is turned on inside "{container_name}" container')
def step_impl(context, container_name):
    os.system("/mnt/c-spiffe/integration_test/helpers/bash-spire-scripts/ssh-generate-token.sh")
    time.sleep(2)
    os.system("/mnt/c-spiffe/integration_test/helpers/bash-spire-scripts/ssh-connect-agent.sh %s %s" % (context.workload_b, container_name))
    time.sleep(7)


@step('The "{language}"-tls-listen is activated inside "{container_name}" container')
def step_impl(context, language, container_name):
    port = context.default_echo_server_port
    if context.current_workload == context.workload_c:
        port = context.second_echo_server_port
    if language == "go":
        os.system("/mnt/c-spiffe/integration_test/helpers/bash-general-scripts/ssh-run-go-server.sh %s %s" %(container_name, port))
        time.sleep(1)
    elif language == "c":
        os.system("/mnt/c-spiffe/integration_test/helpers/bash-spire-scripts/ssh-run-c-server.sh %s %s" %(container_name, port))
        time.sleep(1)
    else:
        raise Exception("'%s' is not an available language for tls-listen. Choose 'c' or 'go'." % language)


@step('The "{language}"-tls-listen is disabled inside "{container_name}" container')
def step_impl(context, language, container_name):
    if language == "go":
        os.system("/mnt/c-spiffe/integration_test/helpers/bash-general-scripts/ssh-stop-go-server.sh %s" % container_name)
    elif language == "c":
        os.system("/mnt/c-spiffe/integration_test/helpers/bash-spire-scripts/ssh-stop-c-server.sh %s" % container_name)
    else:
        raise Exception("'%s' is not an available language for tls-listen. Choose 'c' or 'go'." % language)


@step('I send "{message:NullableString}" to "{container_name}" container through "{language}"-tls-dial')
def step_impl(context, message, container_name, language):
    result = ""
    workload_id = "myworkload%s" % context.current_workload[-1]
    trust_domain = context.default_trust_domain
    port = context.default_echo_server_port
    if context.current_workload == context.workload_c:
        trust_domain = context.second_trust_domain
        port = context.second_echo_server_port

    if language == "go":
        client = subprocess.run(["/mnt/c-spiffe/integration_test/helpers/bash-general-scripts/run-go-client.sh '%s' %s %s %s %s" % (message, container_name, port, trust_domain, workload_id)], stderr=subprocess.PIPE, text=True, shell=True)
        time.sleep(1)
        result = client.stderr
    elif language == "c":
        client = os.popen("/mnt/c-spiffe/build/spiffetls/c_dial '%s' %s %s %s" % (message, socket.gethostbyname(container_name), port, trust_domain))
        result = client.read()
    context.result = result


@then('I check that "{message:NullableString}" was the answer from tls-listen')
def step_impl(context, message):
    tls_answer = context.result.replace("\"","").split("Server replied:")
    actual_message = tls_answer[-1].strip().replace("\\n","")
    assert_that(actual_message, is_(message), "Unexpected response from server: %s" % message)


@step('The second agent is turned on inside "{container_name}" container with the second trust domain')
def step_impl(context, container_name):
    os.system("/mnt/c-spiffe/integration_test/helpers/bash-spire-scripts/ssh-generate-token.sh 2")
    time.sleep(2)
    os.system("/mnt/c-spiffe/integration_test/helpers/bash-spire-scripts/ssh-connect-agent.sh %s %s" % (context.workload_c, container_name))
    time.sleep(7)


@step('I set the "{process}" "{field_alias}" to "{new_value}" inside "{container_name}" container')
def step_impl(context, process, field_alias, new_value, container_name):
    if process != "agent" and process != "server":
        raise Exception("Invalid process '%s' to update the conf file. Choose 'agent' or 'server'." % process)
    workload = ""
    if process == "agent":
        workload = context.current_workload
    if field_alias == "port" and process == "server":
        field_name = "bind_port"
    elif field_alias == "port" and process == "agent":
        field_name = "server_port"
    elif field_alias == "trust domain":
        field_name = "trust_domain"
    elif field_alias == "server address":
        field_name = "server_address"
    elif field_alias in ["data_dir", "directory", "socket_path"]:
            field_name = field_alias
    else:
        raise Exception("Invalid field '%s' to update in the server.conf/agent.conf file." % field_alias)
    os.system("/mnt/c-spiffe/integration_test/helpers/bash-spire-scripts/ssh-update-server-conf.sh %s %s %s %s %s" % (field_name, new_value, process, container_name, workload))


@step('The second server is turned on inside "{container_name}" container')
def step_impl(context, container_name):
    if container_name != "spire-server2":
        raise Exception("Unexpected container to run second server. Use 'spire-server2'.")
    os.system("/mnt/c-spiffe/integration_test/helpers/bash-spire-scripts/ssh-start-server.sh 2")
    time.sleep(5)
    if not is_entry_created(container_name, context.workload_c):
        os.system("/mnt/c-spiffe/integration_test/helpers/bash-spire-scripts/ssh-create-entries.sh 2")


@then('I check that mTLS connection did not succeed')
def step_impl(context):
    assert_that(context.result.find("Server replied:"), is_(-1), "Unexpected response from server: %s" % context.result)
    assert_that(context.result.find("could not create TLS connection"), is_not(-1), "Unexpected error from server: %s" % context.result)


@step('The "{workload_id}" entry is removed from "{container_name}"')
def step_impl(context, workload_id, container_name):
    remove_entry(container_name, workload_id)
