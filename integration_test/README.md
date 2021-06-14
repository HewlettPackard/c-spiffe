# Integration tests

This folder contains all automated integration tests scripts. They were all implemented using Python, with [Behave](https://behave.readthedocs.io/) framework.

## Installing dependencies

- [Docker](https://docs.docker.com/install/)
- [Docker Compose](https://docs.docker.com/compose/install/)

## Building
```
$ cd infra/
$ make build

    Successfully built
```

## Running the tests

```
$ make integration-tests

    docker-compose up -d
    Building with native build. Learn about native build in Compose here: https://docs.docker.com/go/compose-native-build/
    Creating network "infra_default" with the default driver
    Creating infra_spire-server_1 ... done
    Creating infra_workload_1     ... done
    Creating infra_tests_1        ... done

    ....

    4 features passed, 0 failed, 0 skipped
    14 scenarios passed, 0 failed, 6 skipped
    72 steps passed, 0 failed, 32 skipped, 0 undefined
    Took 1m20.920s
    docker-compose down
    Stopping infra_tests_1        ... done
    Stopping infra_workload_1     ... done
    Stopping infra_spire-server_1 ... done
    Removing infra_tests_1        ... done
    Removing infra_workload_1     ... done
    Removing infra_spire-server_1 ... done
    Removing network infra_default
```

### Details inside `$ make integration-tests`

This command encapsulates some steps:
1. Start `infra_tests`, `inrfa_spire-server` and `infra_workload` containers
2. Start `spire-server` process inside `infra_spire-server` container
3. Create `spire-server` entry
4. Generate `spire-server` token which is copied into `infra_tests` container
5. Inside `infra_tests` container, run `run-behave-tests.sh` script, which encapsulates the following:
    - Build binary files examples (the interface to use c-spiffe lib)
    - Run behave tests
        - Before all the tests are run, this stage is also responsible for starting `spire-agent` process inside `infra_tests` container and connect it to the `spire-server` running inside the `infra_spire-server` container
6. Stop `infra_tests`, `infra_spire-server` and `infra_workload` containers
