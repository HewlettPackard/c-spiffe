#!/usr/bin/env bash
TOKEN=$(awk '{ print $2 }' /mnt/c-spiffe/integration_test/myagent$1.token)
if [ $2 ];
then
    ssh root@$2 "`env | sed 's/;/\\\\;/g' | sed 's/.*/set &\;/g'` nohup spire-agent run -joinToken $TOKEN -config /opt/spire/conf/agent/agent.conf> /mnt/c-spiffe/integration_test/agentC.output 2>&1 &"
else
    spire-agent run -joinToken $TOKEN -config /opt/spire/conf/agent/agent.conf &
fi

if [ $? -ne 0 ];
then
echo "error connecting agent\n\n\n"
echo "error connecting agent\n\n\n">/mnt/c-spiffe/integration_test/agent.output
fi
