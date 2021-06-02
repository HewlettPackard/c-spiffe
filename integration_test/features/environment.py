import os
import time


PARENT_PATH = os.path.abspath("..") + "/integration_test/helpers/"


def before_all(context):
    context.spiffe_id = context.config.userdata['spiffe_id']
    context.spire_conf = context.config.userdata['spire_conf']
    context.workload_b = context.config.userdata['workload_b']
    context.workload_c = context.config.userdata['workload_c']
    context.current_workload = ""
    context.default_trust_domain = context.config.userdata['default_trust_domain']
    context.default_echo_server_port = context.config.userdata['default_echo_server_port']
    
    os.system(PARENT_PATH + "bash-spire-scripts/ssh-connect-agent.sh")
    time.sleep(5)


def after_all(context):
    os.system("pkill spire-agent")
    time.sleep(5)
    os.system(PARENT_PATH + "bash-general-scripts/clean.sh")
    time.sleep(1)


def before_feature(context, feature):
    if "mtls" in feature.tags:
        os.system(PARENT_PATH + "bash-general-scripts/clean.sh")
        time.sleep(1)


def before_scenario(context, scenario):
    if context.workload_b in scenario.tags:
        context.current_workload = context.workload_b
        os.system("ssh root@workload \"cp {0}/agent/agent.conf {0}/agent/agent{1}.conf\"".format(context.spire_conf, context.workload_b))
    elif context.workload_c in scenario.tags:
        context.current_workload = context.workload_c
        os.system("ssh root@workload2 \"cp {0}/agent/agent.conf {0}/agent/agent{1}.conf\"".format(context.spire_conf, context.workload_c))


def after_scenario(context, scenario):
    if any(tag in scenario.tags for tag in (context.workload_b, context.workload_c)):
        host_number = ""
        if context.current_workload == context.workload_c:
            host_number = "2"
        os.system("ssh root@workload%s \"rm -rf %s/agent/%s\"" % (host_number, context.spire_conf, context.current_workload))
        context.current_workload = ""
    if "updated-conf" in scenario.tags:
        context.execute_steps('''
            Given I set the "server" "port" to "8081" inside "spire-server2" container
            And   I set the "server" "trust domain" to "example.org" inside "spire-server2" container
            And   I set the "agent" "port" to "8081" inside "workload2" container
            And   I set the "agent" "trust domain" to "example.org" inside "workload2" container
            And   I set the "agent" "server address" to "spire-server" inside "workload2" container
        ''')
        os.system(PARENT_PATH + "bash-general-scripts/clean.sh")
        time.sleep(1)
