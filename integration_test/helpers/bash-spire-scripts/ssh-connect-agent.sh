#!/usr/bin/env bash
TOKEN=$(awk '{ print $2 }' /mnt/c-spiffe/integration_test/myagent$1.token)
if [ $2 ];
then
ssh root@$2 <<EOL
    nohup spire-agent run -joinToken ${TOKEN} -config /opt/spire/conf/agent/agent.conf> /dev/null 2>&1 & 
EOL
else
    spire-agent run -joinToken $TOKEN -config /opt/spire/conf/agent/agent.conf &
fi
