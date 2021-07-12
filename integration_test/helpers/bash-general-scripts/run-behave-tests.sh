#!/usr/bin/env bash
cd /mnt/c-spiffe/build/ && cmake .. && make
cd /mnt/c-spiffe/integration_test && behave --tags=-@wip
