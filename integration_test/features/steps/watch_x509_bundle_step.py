import os
import time

from hamcrest import assert_that, is_not
from utils import is_entry_created


@step('I set the server to rotate the Bundle up to "{time}"')
def step_impl(context, time):
    os.system("/mnt/c-spiffe/integration_test/helpers/bash-spire-scripts/ssh-update-server-conf.sh default_svid_ttl %s server" % time)


@step('I store the "{document}"')
def step_impl(context, document):
    exec("context.current_{0} = context.{0}".format(document.lower()))


@then('The "{document}" was updated')
def step_impl(context, document):
    document = document.lower()
    exec("assert_that(context.%s, is_not('(nil)'), 'Document is empty: (nil)')" % document)
    exec("assert_that(context.{0}, is_not(context.current_{0}), 'Document was not updated.')".format(document))


@step('The server is turned off')
def step_impl(context):
    os.system("/mnt/c-spiffe/integration_test/helpers/bash-spire-scripts/ssh-stop-process.sh server spire-server")
    

@step('The server is turned on')
def step_impl(context):
    os.system("/mnt/c-spiffe/integration_test/helpers/bash-spire-scripts/ssh-start-server.sh")
    time.sleep(5)
    if not is_entry_created("spire-server", context.workload_b):
        os.system("/mnt/c-spiffe/integration_test/helpers/bash-spire-scripts/ssh-create-entries.sh")
