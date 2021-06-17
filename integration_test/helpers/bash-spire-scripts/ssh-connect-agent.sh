#!/usr/bin/env bash
#arguments: $1 = workload_id; $2 = hostname (optional)
TOKEN=$(awk '{ print $2 }' /mnt/c-spiffe/integration_test/myagent$1.token)
if [ $2 ];
then
ssh root@$2 <<EOL
    nohup spire-agent run -joinToken ${TOKEN} -config /opt/spire/conf/agent/agent${1}.conf> /dev/null 2>&1 & 
EOL
else
    spire-agent run -joinToken $TOKEN -config /opt/spire/conf/agent/agent.conf> /dev/null 2>&1 & 
fi
