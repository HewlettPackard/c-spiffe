#!/bin/bash
if [ $1 ];
then 
    ssh root@$1 <<EOL
    spire-server run -config /opt/spire/conf/server/server.conf> /dev/null 2>&1 &
EOL
else
    spire-server run -config /opt/spire/conf/server/server.conf &
fi
