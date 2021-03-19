import os
import sys
import time

from hamcrest import assert_that, is_, is_not


PARENT_PATH = os.path.abspath("..")
if PARENT_PATH not in sys.path:
    sys.path.insert(0, PARENT_PATH)


@when('I fetch "{profile}" "{document}"')
def step_impl(context, profile, document):
    if document == "SVID":
        bin_file = "c_client"
    else:
        bin_file = "c_client_bundle"

    c_client_bin = os.popen("../build/workload/%s %s_type=%s" % (bin_file, document.lower(), profile.lower()))
    context.result = c_client_bin.read()


@then('I check that the "{document}" is returned correctly')
def step_impl(context, document):
    assert_that(context.result.find("error"), is_(-1), "There was an error")
    assert_that(context.result.find("Address: "), is_not(-1), "There is no Address")
    result = context.result.splitlines()
    document_content = result[0].split(" ")[-1]
    if document.lower() == "svid":
        context.svid = document_content
    else:
        context.bundle = document_content
    assert_that(document_content, is_not("(nil)"))


@then('I check that the "{document}" is not returned')
def step_impl(context, document):
    assert_that(context.result.find("error"), is_not(-1), "There was no error")
    assert_that(context.result.find("Address: "), is_not(-1), "There is no Address")
    result = context.result.splitlines()
    document_content = result[1].split(" ")[-1]
    if document.lower() == "svid":
        context.svid = document_content
    else:
        context.bundle = document_content
    assert_that(document_content, is_("(nil)"))


@when('The agent is turned off')
def step_impl(context):
    os.system("pkill spire-agent")
    time.sleep(5)


@when('The agent is turned on')
def step_impl(context):
    os.system("./grpc_generate_token.sh")
    time.sleep(5)
    os.system("./grpc_connect_agent.sh")
    time.sleep(5)
