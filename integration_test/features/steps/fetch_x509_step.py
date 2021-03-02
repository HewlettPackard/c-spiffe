import os
import sys
import json
import base64
import subprocess
import time

PARENT_PATH = os.path.abspath("..")
if PARENT_PATH not in sys.path:
    sys.path.insert(0, PARENT_PATH)

from hamcrest import assert_that, is_, is_not


@when('I fetch SVID')
def step_impl(context):
    c_client_bin = os.popen("../build/workload/c_client")
    result = c_client_bin.read()
    result = result.splitlines()[0]
    context.svid = result.replace("Address : ", "")


@then('I check that the SVID is returned correctly')
def step_impl(context):
    assert_that(context.svid, is_not("(nil)"))


@when('I fetch Bundle')
def step_impl(context):
    c_client_bin = os.popen("../build/workload/c_client_bundle")
    result = c_client_bin.read()
    result = result.splitlines()[0]
    context.bundle = result.replace("Address : ", "")
    

@then('I check that the Bundle is returned correctly')
def step_impl(context):
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


@then('I check that the SVID is not returned')
def step_impl(context):
    assert_that(context.svid, is_("(nil)"))


@then('I check that the Bundle is not returned')
def step_impl(context):
    assert_that(context.bundle, is_("(nil)"))