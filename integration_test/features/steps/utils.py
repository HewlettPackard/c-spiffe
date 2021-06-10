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


def is_wlc_entry_created(container):
    entries = list_entries(container)
    if entries.find("myworkloadC") == -1:
        return False
    return True


def remove_entry(workload_id, container):
    workload = "myworkload%s" % workload_id[-1]
    entries = list_entries(container).split("\n\n")
    for result in entries:
        if result.find(workload) != -1:
            entryId = result.splitlines()[0].split(":")[1].strip()
            os.system("ssh root@%s \"spire-server entry delete -entryID %s\"" % (container, entryId))
