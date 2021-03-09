import os
import sys
import time

from hamcrest import assert_that, is_, is_not


PARENT_PATH = os.path.abspath("..")
if PARENT_PATH not in sys.path:
    sys.path.insert(0, PARENT_PATH)


@when('I fetch "{profile}" SVID')
def step_impl(context, profile):
    c_client_bin = os.popen("../build/workload/c_client svid_type=%s" % profile.lower())
    context.result = c_client_bin.read()


@then('I check that the SVID is returned correctly')
def step_impl(context):
    assert_that(context.result.find("error"), is_(-1), "There was an error")
    assert_that(context.result.find("Address: "), is_not(-1), "There is no Address")
    result = context.result.splitlines()
    context.svid = result[0].split(" ")[-1]
    assert_that(context.svid, is_not("(nil)"))


@then('I check that the SVID is not returned')
def step_impl(context):
    assert_that(context.result.find("error"), is_not(-1), "There was no error")
    assert_that(context.result.find("Address: "), is_not(-1), "There is no Address")
    result = context.result.splitlines()
    context.svid = result[1].split(" ")[-1]
    assert_that(context.svid, is_("(nil)"))


@when('I fetch "{profile}" Bundle')
def step_impl(context, profile):
    c_client_bin = os.popen("../build/workload/c_client_bundle bundle_type=%s" % profile.lower())
    context.result = c_client_bin.read()


@then('I check that the Bundle is returned correctly')
def step_impl(context):
    assert_that(context.result.find("error"), is_(-1), "There was an error")
    assert_that(context.result.find("Address: "), is_not(-1), "There is no Address")
    result = context.result.splitlines()
    context.bundle = result[0].split(" ")[-1]
    assert_that(context.bundle, is_not("(nil)"))


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


@then('I check that the Bundle is not returned')
def step_impl(context):
    assert_that(context.result.find("error"), is_not(-1), "There was no error")
    assert_that(context.result.find("Address: "), is_not(-1), "There is no Address")
    result = context.result.splitlines()
    context.bundle = result[1].split(" ")[-1]
    assert_that(context.bundle, is_("(nil)"))
