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
    #List all process
    processes = os.popen('(ps aux | grep spire-server) > process.txt')
    processes_ids = os.popen('awk \'{ print $2 }\' process.txt ').read().split("\n")
    for id in processes_ids:
        try:
            subprocess.run(["kill", id])
            time.sleep(5)
        except:
            pass
    os.popen('rm process.txt')
    

@when('The server is turned on')
def step_impl(context):
    path = ["spire-server"]
    command = ["run", "-config", "/opt/spire/conf/server/server.conf"]
    process = subprocess.Popen(path + command)
    time.sleep(5)