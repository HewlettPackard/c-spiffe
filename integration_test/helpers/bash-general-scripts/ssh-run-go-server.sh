#!/usr/bin/env bash
#arguments: $1 = hostname; $2 = port
ssh root@$1 "cd /mnt/c-spiffe/integration_test/helpers/go-echo-server/server; su - server-workload -c \"./go-server ${2}\" > /dev/null 2>&1 &"
