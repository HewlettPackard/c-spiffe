#!/usr/bin/env bash
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
