import os
import sys

from pathlib2 import Path


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


def remove_entry(workload_id, container):
    workload = "myworkload%s" % workload_id[-1]
    entries = list_entries(container).split("\n\n")
    for result in entries:
        if result.find(workload) != -1:
            entryId = result.splitlines()[0].split(":")[1].strip()
            os.system("ssh root@%s \"spire-server entry delete -entryID %s\"" % (container, entryId))


def add_federation_block(trust_domain, bundle_endpoint, destination):
    federation_path = "/mnt/c-spiffe/integration_test/resources/federation.conf"
    federation_config_content = Path(federation_path).read_text()
    if federation_config_content.find(trust_domain) == -1:
        update_federation_block(trust_domain, bundle_endpoint)
        federation_config_content = Path(federation_path).read_text()
    server_conf = Path("/opt/spire/conf/server/server.conf")
    #TODO: change it in the destination host
    server_conf_content = server_conf.read_text()
    start_index = server_conf_content.find("server {")
    end_index = server_conf_content.find("}", start_index)-1
    current_value  = server_conf_content[start_index:end_index]
    new_value = current_value + "\n\n" + federation_config_content
    server_conf_content = server_conf_content.replace(current_value, new_value)
    server_conf.write_text(server_conf_content)


def update_federation_block(new_trust_domain, new_bundle_endpoint):
    path = Path("/mnt/c-spiffe/integration_test/resources/federation.conf")
    content = path.read_text()
    trust_domain_field = "federates_with \""
    content, start_index = replace_text_content(content, trust_domain_field, new_trust_domain)
    bundle_endpoint_field = "address = \""
    content, start_index = replace_text_content(content, bundle_endpoint_field, new_bundle_endpoint, start_index)
    path.write_text(content)


def replace_text_content(content, field, new_value, edge_index=0):
    start_index = content.find(field, edge_index) + len(field)
    end_index = content.find("\"",start_index)
    current_value = content[start_index:end_index]
    content = content.replace(current_value, new_value)
    return content, start_index
