import os
import sys
import json
import argparse

from urllib.parse import unquote


def before_all(context):
    context.spiffe_id        = context.config.userdata['spiffe_id']
