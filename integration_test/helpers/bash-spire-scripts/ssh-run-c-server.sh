#!/usr/bin/env bash
#arguments: $1 = hostname; $2 = port
ssh root@$1 "cd /mnt/c-spiffe/build/spiffetls; su - server-workload -c \"./c_listen ${2}\" > /dev/null 2>&1 &"
