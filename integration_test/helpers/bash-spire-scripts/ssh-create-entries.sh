#!/bin/bash
#arguments: $1 = hostname numeration (optional)
if [ $1 ];
then
    ssh root@spire-server$1 << "EOL" 
    spire-server entry create -parentID spiffe://example2.org/myagent -spiffeID spiffe://example2.org/myworkloadC -selector unix:user:server-workload>>/opt/spire/conf/server/entry2.output
    spire-server entry create -parentID spiffe://example2.org/myagent -spiffeID spiffe://example2.org/myworkloadC -selector unix:user:root>>/opt/spire/conf/server/entry2.output
EOL
else
    ssh root@spire-server << "EOL" 
    spire-server entry create -parentID spiffe://example.org/myagent -spiffeID spiffe://example.org/myworkloadA -selector unix:user:client-workload
    spire-server entry create -parentID spiffe://example.org/myagent -spiffeID spiffe://example.org/myworkloadA -selector unix:user:root
    spire-server entry create -parentID spiffe://example.org/myagent -spiffeID spiffe://example.org/myworkloadB -selector unix:user:server-workload
EOL
fi
