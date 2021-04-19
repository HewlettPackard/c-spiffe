#!/usr/bin/env bash
ssh root@$1 << "EOL" 
kill -9 `ps aux | grep go | awk '{print $2}'`
EOL
