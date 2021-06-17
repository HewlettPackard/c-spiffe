#!/usr/bin/env bash
#arguments: $1 = hostname
mkdir ~/.ssh
if [ $1 = "workload" ];
then
cp /mnt/c-spiffe/integration_test/helpers/bash-general-scripts/authorized_keys ~/.ssh
elif [ $1 = "spire-server" ];
then
cp /opt/spire/authorized_keys ~/.ssh
fi
