#!/bin/bash
if [ $3 ];
then
    ssh root@$3 <<EOL 
    sed -i 's/'$1' = "\([^"]\)*"/'$1' = "'$2'"/' /opt/spire/conf/server/server.conf
EOL
else
    sed -i 's/'$1' = "\([^"]\)*"/'$1' = "'$2'"/' /opt/spire/conf/server/server.conf
fi
