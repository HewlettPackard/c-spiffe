import os
import time


PARENT_PATH = os.path.abspath("..") + "/integration_test/helpers/"


def before_all(context):
    context.spiffe_id = context.config.userdata['spiffe_id']
    
    os.system(PARENT_PATH + "bash-spire-scripts/ssh-connect-agent.sh")
    time.sleep(5)


def after_all(context):
    os.system("pkill spire-agent")
    time.sleep(5)
    os.system(PARENT_PATH + "bash-general-scripts/clean.sh")
    time.sleep(1)


def after_scenario(context, scenario):
    if "updated-conf" in scenario.tags:
        context.execute_steps('''
            Given I set the "server" "port" to "8081" inside "spire-server2" container
            And   I set the "server" "trust domain" to "example.org" inside "spire-server2" container
            And   I set the "agent" "port" to "8081" inside "workload" container
            And   I set the "agent" "trust domain" to "example.org" inside "workload" container
            And   I set the "agent" "server address" to "spire-server" inside "workload" container
        ''')
