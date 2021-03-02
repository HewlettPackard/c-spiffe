import os
import subprocess
import time

from hamcrest import assert_that, is_, is_not
from utils import update_server_conf


@given('I set the server to rotate the Bundle up to "{time}"')
def step_impl(context, time):
    update_server_conf("../infra/spire-server/server.conf", "default_svid_ttl", time)


@when('I store the Bundle')
def step_impl(context):
    context.current_bundle = context.bundle


@then('The Bundle was updated')
def step_impl(context):
    assert_that(context.bundle, is_not("(nil)"))
    assert_that(context.bundle, is_not(context.current_bundle))


@when('The server is turned off')
def step_impl(context):
    os.system("pkill spire-server")
    time.sleep(5)
    

@when('The server is turned on')
def step_impl(context):
    os.system("./grpc_start_server.sh")
    time.sleep(5)


@when('I create server entries')
def step_impl(context):
    os.system("./grpc_create_entries.sh")
    time.sleep(1)
