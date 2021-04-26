build:
	docker build spire-agent -t spire-agent
	docker-compose build

build-tests-workload:
	docker-compose exec workload ./build-tests-workload.sh

run:
	docker-compose up -d

run-server:
	docker-compose exec spire-server spire-server run

create-entries:
	docker-compose exec spire-server ./create-entries.sh

generate-token:
	docker-compose exec spire-server spire-server token generate -spiffeID spiffe://example.org/host

join-token:
	docker-compose exec $(SERVICE) spire-agent run -joinToken $(TOKEN) -config /opt/spire/conf/agent/agent.conf

clean:
	docker-compose down

integration-tests:
	docker-compose up -d
	docker exec infra_spire-server_1 spire-server run &
	sleep 1
	docker exec infra_spire-server_1 spire-server entry create -parentID spiffe://example.org/myagent -spiffeID spiffe://example.org/myworkload -selector unix:user:root
	docker exec infra_spire-server_1 spire-server token generate -spiffeID spiffe://example.org/myagent > myagent.token && docker cp myagent.token infra_tests_1:/mnt/c-spiffe/integration_test
	docker exec -w /mnt/c-spiffe/integration_test infra_tests_1 chmod +x ./run-behave-tests.sh
	docker exec -w /mnt/c-spiffe/integration_test infra_tests_1 ./run-behave-tests.sh
	docker-compose down

spiffetls-run:
#	microservices up
	docker-compose up -d

#	spire-server up
	docker exec infra_spiffetls-test_1 spire-server run &
	sleep 1

#	create entries
	docker exec infra_spiffetls-test_1 spire-server entry create -spiffeID spiffe://example.org/server -parentID spiffe://example.org/host -selector unix:user:server-workload
	docker exec infra_spiffetls-test_1 spire-server entry create -spiffeID spiffe://example.org/client -parentID spiffe://example.org/host -selector unix:user:client-workload

spiffetls-generate-token:
#	generate token
	docker exec infra_spiffetls-test_1 spire-server token generate -spiffeID spiffe://example.org/host

spiffetls-join-token:
#	connect with server
	docker exec infra_spiffetls-test_1 spire-agent run -joinToken $(TOKEN) &
