#!/usr/bin/env bash
ssh root@$1 << "EOL"
/mnt/c-spiffe/integration_test/helpers/bash-spire-scripts/grpc_connect_agent.sh WlB > /dev/null 2>&1 &
EOL
