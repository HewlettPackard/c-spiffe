#!/usr/bin/env bash
if [ $4 ];
then 
    ssh root@$4 <<EOL
    /mnt/c-spiffe/build/workload/${1} ${2}_type=${3}
EOL
else
    /mnt/c-spiffe/build/workload/${1} ${2}_type=${3}
fi
