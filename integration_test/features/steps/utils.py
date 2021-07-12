import os
import sys
import time
import re

from pathlib2 import Path
from subprocess import call


PARENT_PATH = os.path.abspath("..")
if PARENT_PATH not in sys.path:
    sys.path.insert(0, PARENT_PATH)


def parse_nullable_string(text):
    return text


def parse_optional(text):
    return text.strip()


def list_entries(container):
    return os.popen("ssh root@%s \"spire-server entry show\"" % container).read()


def is_entry_created(container, workload_id):
    id = workload_id[-1]
    if id == "A": id = ""
    entries = list_entries(container)
    if entries.find("myworkload%s" % id) == -1:
        return False
    return True


def remove_entry(container, workload_id="A"):
    workload = "myworkload%s" % workload_id[-1]
    entries = list_entries(container).split("\n\n")
    try:
        entries_found = re.findall("Found \d entries\n", entries[0])[0]
        entries[0] = entries[0].replace(entries_found,"")
    except IndexError:
        pass
    for result in entries:
        if result.find(workload) != -1:
            entryId = result.splitlines()[0].split(":")[1].strip()
            os.system("ssh root@%s \"spire-server entry delete -entryID %s\"" % (container, entryId))
    time.sleep(7)


def replace_text_content(content, field, new_value, edge_index=0):
    start_index = content.find(field, edge_index) + len(field)
    end_index = content.find("\"",start_index)
    current_value = content[start_index:end_index]
    content = content.replace(current_value, new_value)
    return content, start_index
    

def update_federation_block(new_trust_domain, new_bundle_endpoint):
    content = Path("/mnt/c-spiffe/integration_test/resources/federation.conf").read_text()
    trust_domain_field = "federates_with \""
    content, start_index = replace_text_content(content, trust_domain_field, new_trust_domain)
    bundle_endpoint_field = "address = \""
    content, start_index = replace_text_content(content, bundle_endpoint_field, new_bundle_endpoint, start_index)
    return content


def copy_file_from_remote(remote, file_path):
    cmd = "scp root@{0}:{1} {1}".format(remote, file_path)
    call(cmd.split(" "))
    time.sleep(2)


def send_file_to_remote(remote, file_path):
    cmd = "scp {0} root@{1}:{0}".format(file_path, remote)
    call(cmd.split(" "))
    time.sleep(2)


def add_federation_block(trust_domain, bundle_endpoint, remote):
    federation_path = "/mnt/c-spiffe/integration_test/resources/federation.conf"
    federation_config_content = Path(federation_path).read_text()
    if federation_config_content.find(trust_domain) == -1:
        federation_config_content = update_federation_block(trust_domain, bundle_endpoint)
    
    server_conf_path = "/opt/spire/conf/server/server.conf"
    copy_file_from_remote(remote, server_conf_path)
    server_conf = Path(server_conf_path)
    server_conf_content = server_conf.read_text()
    start_index = server_conf_content.find("server {")
    end_index = server_conf_content.find("}", start_index)-1
    current_value  = server_conf_content[start_index:end_index]
    new_value = current_value + "\n\n" + federation_config_content + "\n"
    server_conf_content = server_conf_content.replace(current_value, new_value)
    server_conf.write_text(server_conf_content)
    send_file_to_remote(remote, server_conf_path)


def remove_federation_block(remote):
    server_conf_path = "/opt/spire/conf/server/server.conf"
    copy_file_from_remote(remote, server_conf_path)
    server_conf = Path(server_conf_path)
    server_conf_content = server_conf.read_text()
    start_index = server_conf_content.find("\n\n    federation")
    federation_limit = "}\n        }\n    }\n\n"
    end_index = server_conf_content.find(federation_limit, start_index) + len(federation_limit)
    federation_block = server_conf_content[start_index:end_index]
    server_conf_content = server_conf_content.replace(federation_block, "")
    server_conf.write_text(server_conf_content)
    send_file_to_remote(remote, server_conf_path)


def create_federation_entries(hostname, trust_domain, federated_trust_domain, workload_id="A"):
    workload_id = workload_id[-1]
    user = "client-workload"
    if workload_id == "C":
        user = "server-workload"
    elif workload_id == "A":
        run_federation_entries_creation(hostname, trust_domain, federated_trust_domain, workload_id, "root")    
    run_federation_entries_creation(hostname, trust_domain, federated_trust_domain, workload_id, user)
    

def run_federation_entries_creation(hostname, trust_domain, federated_trust_domain, workload_id, user):
    os.system("ssh root@{0} spire-server entry create \
	-parentID spiffe://{1}/myagent \
	-spiffeID spiffe://{1}/myworkload{3} \
	-selector unix:user:{4} \
	-federatesWith \"spiffe://{2}\"".format(hostname, trust_domain, federated_trust_domain, workload_id, user))
