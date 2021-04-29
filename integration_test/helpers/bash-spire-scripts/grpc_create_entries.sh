#!/bin/bash
spire-server entry create -parentID spiffe://example.org/myagent -spiffeID spiffe://example.org/myworkload -selector unix:user:root &
