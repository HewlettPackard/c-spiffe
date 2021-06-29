#arguments: $1 = 'server' (optional)
rm -rf /mnt/c-spiffe/integration_test/data
rm -rf /mnt/c-spiffe/integration_test/helpers/bash-spire-scripts/data
ssh root@workload "rm -rf /mnt/c-spiffe/integration_test/data && rm -rf /mnt/c-spiffe/integration_test/helpers/bash-spire-scripts/data && rm -rf /mnt/c-spiffe/build/data"
ssh root@workload2 "rm -rf /mnt/c-spiffe/integration_test/data && rm -rf /mnt/c-spiffe/integration_test/helpers/bash-spire-scripts/data && rm -rf /mnt/c-spiffe/build/data"
if [ $1 ];
then
ssh root@spire-server "rm -rf /opt/spire/data"
ssh root@spire-server2 "rm -rf /opt/spire/data"
fi
