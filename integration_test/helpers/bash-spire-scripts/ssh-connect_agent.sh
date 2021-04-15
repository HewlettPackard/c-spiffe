#!/usr/bin/env bash
ssh root@$1 << "EOL"
./grpc_connect_agent.sh WlB &
EOL