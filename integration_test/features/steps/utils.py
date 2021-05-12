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


def update_server_conf(file_path, field, new_value):
    path = Path(file_path)
    content = path.read_text()

    field = "%s = \"" % field
    start_index = content.find(field) + len(field)
    end_index = content.find("\"",start_index)

    current_value = content[start_index:end_index]
    content = content.replace(current_value, new_value)
    path.write_text(content)
