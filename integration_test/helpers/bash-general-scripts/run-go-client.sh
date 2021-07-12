#!/usr/bin/env bash
#arguments: $1 = message_to_send; $2 = listener_hostname; $3 = listener_port; $4 = listener_trust_domain; $5 = listener_workload_id
cd /mnt/c-spiffe/integration_test/helpers/go-echo-server/client && su - client-workload -c "./go-client '$1' $2 $3 $4 $5"
