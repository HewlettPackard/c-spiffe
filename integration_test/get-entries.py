# (C) Copyright 2020-2021 Hewlett Packard Enterprise Development LP
#
# 
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
# 
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# 
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

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
