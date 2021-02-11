#!/bin/bash
mv ./spire /opt/spire
cd /opt/spire/bin

#server 
echo ./spire-server run -config /opt/spire/conf/server/server.conf
./spire-server run -config /opt/spire/conf/server/server.conf
