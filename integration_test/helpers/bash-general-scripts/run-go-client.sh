#!/usr/bin/env bash
cd /mnt/c-spiffe/integration_test/helpers/go-echo-server/client && su - client-workload -c "./go-client '$1'"
