#!/bin/bash
#arguments: $1 = hostname numeration (optional)
if [ $1 ];
then
    ssh root@spire-server$1 "`env | sed 's/;/\\\\;/g' | sed 's/.*/set &\;/g'` spire-server token generate -spiffeID spiffe://example${1}.org/myagent>/opt/spire/myagentWlC.token"
    cd /mnt/c-spiffe/integration_test && scp root@spire-server$1:/opt/spire/myagentWlC.token .
else
    ssh root@spire-server "`env | sed 's/;/\\\\;/g' | sed 's/.*/set &\;/g'` spire-server token generate -spiffeID spiffe://example.org/myagent>/opt/spire/myagent.token"
    cd /mnt/c-spiffe/integration_test && scp root@spire-server:/opt/spire/myagent.token .
    ssh root@spire-server "`env | sed 's/;/\\\\;/g' | sed 's/.*/set &\;/g'` spire-server token generate -spiffeID spiffe://example.org/myagent>/opt/spire/myagentWlB.token"
    cd /mnt/c-spiffe/integration_test && scp root@spire-server:/opt/spire/myagentWlB.token .
spire-server token generate -spiffeID spiffe://example.org/myagent>/mnt/c-spiffe/integration_test/myagent$1.token
fi
