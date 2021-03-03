#!/bin/bash
apt update
yes Y | apt-get install python3-pip
python3 -m pip install -r requirements.txt
chmod 777 /mnt/integration_test/grpc_conn_test_agent.sh  /mnt/integration_test/grpc_conn_test_entries.sh  /mnt/integration_test/grpc_conn_test_server.sh
