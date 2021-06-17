#!/usr/bin/env bash
#arguments: $1 = 'c_client' or 'c_client_bundle'; $2 = 'svid' or 'bundle'; $3 = 'x509' or 'jwt'; $4 = hostname (optional)
if [ $4 ];
then 
    ssh root@$4 <<EOL
    cd /mnt/c-spiffe/build/workload/
    su - server-workload -c "./${1} ${2}_type=${3}"
EOL
else
    /mnt/c-spiffe/build/workload/${1} ${2}_type=${3}
fi
