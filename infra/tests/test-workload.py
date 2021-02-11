#!/usr/bin/env python

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
