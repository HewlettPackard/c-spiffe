import os
import sys
import string

from os import chdir
from common.constants import Paths


PARENT_PATH = os.path.abspath("..")
if PARENT_PATH not in sys.path:
    sys.path.insert(0, PARENT_PATH)


def handle_response(response, function_name, expected_status_code):
    if response.status_code != expected_status_code:
        print("request: " + function_name + " - status_code: " + str(response.status_code) + " - message: " + response.text)


def print_exception(function_name, error):
    print(function_name + str(error))
