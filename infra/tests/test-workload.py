#!/usr/bin/env python
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


import ctypes

def check_so(soname):
    try:
        lib = ctypes.cdll.LoadLibrary(soname)
        print("INFO: Found so as", lib)
        return True
    except OSError as ex:
        print("WARNING:", ex)
        return False


if __name__ == "__main__":
    # "./liblibbundle.so"
    # "./liblibinternal.so"
    # "./liblibspiffeid.so"
    # "./liblibsvid.so")
    
    j = check_so("./liblibrequestor.so")
    if not j:
        print("Error: Could not test")
    else:
        print("Success: J %s  \n" % j)
