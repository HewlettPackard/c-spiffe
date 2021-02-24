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


@when(u'I fetch SVID')
def step_impl(context):
    c_client_bin = os.popen("../build/workload/c_client")
    result = c_client_bin.read()
    result = result.splitlines()[0]
    context.svid = result.replace("Address : ", "")


@then(u'I check that the SVID is returned correctly')
def step_impl(context):
    assert_that(context.svid, is_not("(nil)"))


@when(u'I fetch bundle')
def step_impl(context):
    c_client_bin = os.popen("../build/workload/c_client_bundle")
    result = c_client_bin.read()
    result = result.splitlines()[0]
    context.bundle = result.replace("Address : ", "")
    

@then(u'I check that the Bundle is returned correctly')
def step_impl(context):
    assert_that(context.bundle, is_not("(nil)"))


@when(u'I down the server')
def step_impl(context):
    #List all process
    processes = os.popen('ps aux | grep spire-agent')
    result = processes.read()
    result = result.splitlines()[0]
    process_id_1 = result[12:-125]
    process_id_2 = result[12:-155]
    down_process = subprocess.run(["kill", process_id_1])
    down_process = subprocess.run(["kill", process_id_2])
    time.sleep(5)


@when(u'I up the server')
def step_impl(context):
    path = ["spire-agent"]
    command = ["run", "-joinToken", "$TOKEN", "-config", "/opt/spire/conf/agent/agent.conf"]
    process = subprocess.Popen(path + command)
    time.sleep(5)


@then(u'I check that the SVID is not returned')
def step_impl(context):
    assert_that(context.svid, is_("(nil)"))


@then(u'I check that the Bundle is not returned')
def step_impl(context):
    assert_that(context.bundle, is_("(nil)"))