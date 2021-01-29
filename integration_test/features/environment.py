import os
import sys
import json
import argparse

from urllib.parse import unquote


def before_all(context):
    context.spiffe_id        = context.config.userdata['spiffe_id']
    context.SPIFFE_ID_       = context.config.userdata['SPIFFE_ID_']
    context.token            = context.config.userdata['token']
    context.Parent_ID_       = context.config.userdata['Parent_ID_']
