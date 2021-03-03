import os
import time


def before_all(context):
    context.spiffe_id = context.config.userdata['spiffe_id']
    context.server_conf = context.config.userdata['server_conf']
    
    os.system("./grpc_start_server.sh")
    time.sleep(5)
    os.system("./grpc_create_entries.sh")
    time.sleep(1)
    os.system("./grpc_generate_token.sh")
    time.sleep(5)
    os.system("./grpc_connect_agent.sh")
    time.sleep(5)


def after_all(context):
    os.system("pkill spire-agent")
    time.sleep(5)
    os.system("pkill spire-server")
    time.sleep(5)
    os.system("./clean.sh")
    time.sleep(1)