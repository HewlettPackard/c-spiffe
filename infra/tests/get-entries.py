#!/usr/bin/env python

import os

import logging
import sys

logging.basicConfig(stream=sys.stderr, level=logging.DEBUG)


def check_entries():
    logging.info("Getting Entries from SPIRE server...")
    
    bashCommand = "./get-entries.sh";
    
    output = os.system(bashCommand)
    
    logging.info("entries:" + str(output));
    
    return output


if __name__ == "__main__":
    j = check_entries()
    if not j:
        print("Error: Could not retrieve entries")
    else:
        print("Success: found entries %s  \n" % j)
