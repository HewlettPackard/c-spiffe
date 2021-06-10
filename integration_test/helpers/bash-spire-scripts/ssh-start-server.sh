#!/bin/bash
#arguments: $1 = hostname numeration (optional)
ssh root@spire-server$1 <<EOL
    spire-server run -config /opt/spire/conf/server/server.conf> /dev/null 2>&1 &
EOL
