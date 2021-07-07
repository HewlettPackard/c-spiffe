#!/usr/bin/env bash
#arguments: $1 = hostname; $2 = port
ssh root@$1 << "EOL" 
cd /mnt/c-spiffe/integration_test/helpers/go-echo-server/server
su - server-workload -c "./go-server ${2}" > /mnt/c-spiffe/integration_test/go-listen.log 2>&1 &
EOL
