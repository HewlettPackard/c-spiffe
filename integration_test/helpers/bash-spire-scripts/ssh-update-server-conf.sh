# (C) Copyright 2020-2021 Hewlett Packard Enterprise Development LP
#
# 
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
# 
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# 
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

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
