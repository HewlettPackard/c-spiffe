#!/usr/bin/env bash
ssh root@$1 << "EOL" 
cd /mnt/c-spiffe/integration_test/helpers/go-echo-server/server
go run server.go > /dev/null 2>&1 &
EOL

