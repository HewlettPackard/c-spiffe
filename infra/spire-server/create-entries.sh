#!/usr/bin/env bash
set -x
spire-server entry create -parentID spiffe://example.org/host -spiffeID spiffe://example.org/workload -selector unix:uid:1001 -ttl 3600
spire-server entry create -parentID spiffe://example.org/host -spiffeID spiffe://example.org/tests -selector unix:uid:1002 -ttl 3600

