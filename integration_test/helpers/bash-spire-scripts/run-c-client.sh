#!/usr/bin/env bash
#arguments: $1 = message_to_send; $2 = hostname_IP_address; $3 = server_port; $4 = trust_domain 
cd /mnt/c-spiffe/build/spiffetls
su - client-workload -c "./c_dial '$1' $2 $3 $4" > /dev/null 2>&1 &
