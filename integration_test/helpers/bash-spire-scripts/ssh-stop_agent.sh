#!/usr/bin/env bash
ssh root@$1 << "EOL" 
pkill spire-agent
EOL