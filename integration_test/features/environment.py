import os
import time
import sys

from pathlib2 import Path


PARENT_PATH = os.path.abspath("..") + "/integration_test/helpers/"


def before_all(context):
    context.spiffe_id = context.config.userdata['spiffe_id']
    context.server_conf = context.config.userdata['server_conf']
    
    os.system(PARENT_PATH + "bash-spire-scripts/grpc_connect_agent.sh")
    time.sleep(5)


def after_all(context):
    os.system("pkill spire-agent")
    time.sleep(5)
    os.system(PARENT_PATH + "bash-general-scripts/clean.sh")
    time.sleep(1)