#!/bin/bash
#arguments: $1 = field to be updated; $2 = new value for the field; $3 = 'server' or 'agent'; $4 = hostname (optional); $5 = workload_id (optional)
if [ $4 ];
then
    ssh root@$4 <<EOL 
    sed -i 's#'$1' = "\([^"]\)*"#'$1' = "'$2'"#' /opt/spire/conf/'$3'/'$3''$5'.conf
EOL
else
    sed -i 's#'$1' = "\([^"]\)*"#'$1' = "'$2'"#' /opt/spire/conf/$3/$3.conf
fi
