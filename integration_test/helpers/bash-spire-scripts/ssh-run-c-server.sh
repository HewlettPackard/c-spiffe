#!/usr/bin/env bash
#arguments: $1 = hostname
ssh root@$1 <<EOL
cd /mnt/c-spiffe/build/spiffetls
su - server-workload -c "./c_listen" > /dev/null 2>&1 &
EOL
