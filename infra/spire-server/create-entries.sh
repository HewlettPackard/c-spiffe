#!/usr/bin/env bash
set -x
spire-server entry create -parentID spiffe://example.org/myagent -spiffeID spiffe://example.org/myworkload -selector unix:user:root
spire-server entry create -parentID spiffe://example.org/host -spiffeID spiffe://example.org/tests -selector unix:uid:1002
spire-server entry create -parentID spiffe://example.org/host -spiffeID spiffe://example.org/tests -selector unix:user:root
