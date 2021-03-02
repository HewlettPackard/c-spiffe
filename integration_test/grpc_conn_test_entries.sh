#!/bin/bash


# entries
echo ./spire-server entry create -parentID spiffe://example.org/myagent -spiffeID spiffe://example.org/myworkload -selector unix:user:root
spire-server entry create -parentID spiffe://example.org/myagent -spiffeID spiffe://example.org/myworkload -selector unix:user:root
echo ./spire-server entry create -parentID spiffe://example.org/myagent -spiffeID spiffe://example.org/myworkload_example -selector unix:user:example
spire-server entry create -parentID spiffe://example.org/myagent -spiffeID spiffe://example.org/myworkload_example -selector unix:user:example
echo "PRESS ENTER"
read aaa
#later
echo ./spire-server entry create -parentID spiffe://example.org/myagent -spiffeID spiffe://example.org/myworkload_example2 -selector unix:user:example
spire-server entry create -parentID spiffe://example.org/myagent -spiffeID spiffe://example.org/myworkload_example2 -selector unix:user:example
