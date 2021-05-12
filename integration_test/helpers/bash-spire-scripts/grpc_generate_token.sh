#!/bin/bash
ssh root@spire-server$2 <<EOL
TOKEN=(spire-server token generate -spiffeID spiffe://example.org/myagent)
echo external $TOKEN
EOL
echo internal $TOKEN

# ssh root@$2 "`env | sed 's/;/\\\\;/g' | sed 's/.*/set &\;/g'` spire-agent run -joinToken $TOKEN -config /opt/spire/conf/agent/agent.conf> /dev/null 2>&1 &"
# (spire-server'$2' token generate -spiffeID spiffe://example'$2'.org/myagent) > /mnt/c-spiffe/integration_test/myagent'$1'.token &
