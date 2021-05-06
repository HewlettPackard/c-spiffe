#!/usr/bin/env bash
if [ $2 ];
then
ssh root@$1 << "EOL"
/mnt/c-spiffe/integration_test/helpers/bash-spire-scripts/grpc_connect_agent.sh WlC other> /dev/null 2>&1 &
EOL
else
ssh root@$1 << "EOL"
/mnt/c-spiffe/integration_test/helpers/bash-spire-scripts/grpc_connect_agent.sh WlB> /dev/null 2>&1 &
EOL
fi
