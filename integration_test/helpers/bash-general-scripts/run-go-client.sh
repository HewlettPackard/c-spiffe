#!/usr/bin/env bash
#arguments: $1 = message_to_send; $2 = listener_hostname
cd /mnt/c-spiffe/integration_test/helpers/go-echo-server/client && su - client-workload -c "./go-client '$1' $2"
