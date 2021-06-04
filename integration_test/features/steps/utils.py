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


def is_wlc_entry_created(container):
    entries = os.popen("ssh root@%s \"spire-server entry show\"" % container).read()
    if entries.find("myworkloadC") == -1:
        return False
    return True
