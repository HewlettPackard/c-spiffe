#!/usr/bin/env bash
ssh root@$1 << "EOL" 
pkill go-server
EOL
