#!/usr/bin/env bash
#arguments: $1 hostname
cd /mnt/c-spiffe/build/spiffetls
su - server-workload -c "./c_listen" > /dev/null 2>&1 &
/mnt/c-spiffe/build/spiffetls/c_dial '%s' %s %s %s
