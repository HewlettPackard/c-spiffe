# c-spiffe

C extension for Spiffe platform.

## Introduction

gRPC C++ examples built with CMake.

## Files

```
.
├── bundle
│   ├── CMakeLists.txt
│   ├── jwtbundle
│   │   ├── src
│   │   │   ├── bundle.c
│   │   │   ├── bundle.h
│   │   │   ├── set.c
│   │   │   └── set.h
│   │   └── tests
│   │       ├── check_bundle.c
│   │       ├── jwk_keys.json
│   │       └── README
│   ├── spiffebundle
│   │   └── src
│   │       ├── bundle.c
│   │       ├── bundle.h
│   │       ├── set.c
│   │       └── set.h
│   └── x509bundle
│       ├── src
│       │   ├── bundle.c
│       │   ├── bundle.h
│       │   ├── set.c
│       │   └── set.h
│       └── tests
│           ├── certs.pem
│           ├── check_bundle.c
│           ├── check_set.c
│           └── README
├── cmake
│   ├── config.h.in
│   ├── COPYING-CMAKE-SCRIPTS.txt
│   └── FindCheck.cmake
├── CMakeLists.txt
├── docker
│   └── grpc.Dockerfile
├── file
├── img
│   └── ci-process.png
├── integration_test
│   ├── behave.ini
│   ├── common
│   │   ├── assets
│   │   │   ├── good-cert-and-key.pem
│   │   │   └── good-key-and-cert.pem
│   │   └── constants.py
│   ├── features
│   │   ├── environment.py
│   │   ├── steps
│   │   │   └── SVID_step.py
│   │   ├── TS_SVID.feature
│   │   └── utils.py
│   ├── get-entries.py
│   ├── get-entries.sh
│   ├── README.md
│   ├── requirements.txt
│   └── test.txt
├── internal
│   ├── CMakeLists.txt
│   ├── cryptoutil
│   │   ├── src
│   │   │   ├── keys.c
│   │   │   └── keys.h
│   │   └── tests
│   │       ├── check_keys.c
│   │       ├── CMakeLists.txt
│   │       └── README
│   ├── jwtutil
│   │   ├── src
│   │   │   ├── util.c
│   │   │   └── util.h
│   │   └── tests
│   │       ├── check_util.c
│   │       ├── CMakeLists.txt
│   │       └── README
│   ├── pemutil
│   │   ├── src
│   │   │   ├── pem.c
│   │   │   └── pem.h
│   │   └── tests
│   │       ├── check_pem.c
│   │       ├── CMakeLists.txt
│   │       └── README
│   └── x509util
│       ├── src
│       │   ├── certpool.c
│       │   ├── certpool.h
│       │   ├── util.c
│       │   └── util.h
│       └── tests
│           ├── certs.pem
│           ├── check_certpool.c
│           ├── check_util.c
│           ├── CMakeLists.txt
│           ├── key-pkcs8-rsa.pem
│           ├── README
│           └── resources
│               ├── certs.pem
│               └── key-pkcs8-rsa.pem
├── proto
│   └── spiffe
│       └── workload
│           ├── README.md
│           └── workload.proto
├── protos
│   └── workload.proto
├── README.md
├── spiffeid
│   ├── CMakeLists.txt
│   ├── src
│   │   ├── id.c
│   │   ├── id.h
│   │   ├── match.c
│   │   ├── match.h
│   │   ├── trustdomain.c
│   │   └── trustdomain.h
│   └── tests
│       ├── check_id.c
│       ├── check_match.c
│       ├── check_trustdomain.c
│       ├── CMakeLists.txt
│       └── README
├── spiffetls
│   └── tlsconfig
│       └── src
│           ├── authorizer.c
│           └── authorizer.h
├── svid
│   ├── CMakeLists.txt
│   └── x509svid
│       ├── src
│       │   ├── svid.c
│       │   ├── svid.h
│       │   ├── verify.c
│       │   └── verify.h
│       └── tests
│           ├── check_svid.c
│           ├── check_verify.c
│           ├── CMakeLists.txt
│           ├── README
│           └── resources
│               ├── good-cert-and-key.pem
│               ├── good-key-and-cert.pem
│               ├── good-leaf-and-intermediate.pem
│               ├── good-leaf-only.pem
│               ├── key-pkcs8-ecdsa.pem
│               └── key-pkcs8-rsa.pem
├── utils
│   ├── src
│   │   ├── stb_ds.h
│   │   ├── util.c
│   │   └── util.h
│   └── tests
│       ├── check_util.c
│       ├── README
│       └── test.txt
└── workload
    ├── CMakeLists.txt
    ├── src
    │   ├── c_client_example.c
    │   ├── client.cc
    │   ├── client.h
    │   ├── cpp_client_example.cc
    │   ├── EXAMPLE.md
    │   ├── grpc_conn_test.cc
    │   ├── requestor.cc
    │   └── requestor.h
    └── tests
        ├── check_client.cc
        ├── check_requestor.c
        ├── check_requestor.cc
        ├── CMakeLists.txt
        └── resources
            └── certs.pem
```

## Dependencies

* gRPC 1.34
* CMake 3.13.0+

##  Build Docker Image

```
docker build -f docker/grpc.Dockerfile --build-arg GPRC_VERSION=1.34.0 --build-arg NUM_JOBS=8 --tag grpc-build:1.34.0 .
```

## Run Docker Container

#### setting volume path: <code>/mnt</code>

```
docker run -it --rm --network host -v $(pwd):/mnt grpc-build:1.34.0
```

# For Windows 

```
docker run -it --rm --network host -v //c/Repositorios/c-spiffe:/mnt grpc-build:1.34.0
```

## Building
Build the c-spiffe project:
```
cd /mnt
mkdir build && cd build
cmake ..
make
make test
```
After running `make test`, you will find the test files into `Testing` folder.

### Code Coverage Support

This implements Code Coverage Reports using either using either `gcov` or `lcov`.
If you want to check them, you should run the following command after `make test`:

```
make gcov
make lcov
```

The coverage reports will be into `Coverage` folder. In the case of `lcov`, you
can see into the browser, opening the `index.html` file on the folder above.

# Continuous Integration (CI)

## Operation

Continuous integration (CI) is a practice where a team of developers integrate their code early and often to the main branch or code repository. The goal is to reduce the risk of seeing “integration hell” by waiting for the end of a project or a sprint to merge the work of all developers.

To adopt continuous integration, we will need to run your tests on every change that gets pushed back to the main branch. To do so, you will need to have a service that can monitor your repository and listen to new pushes to the codebase. 

![Alt text](img/ci-process.png "Commit, Build and Deploy")

# The .gitlab-ci.yml file
To use GitLab CI/CD, you need:

Application code hosted in a Git repository.
A file called .gitlab-ci.yml in the root of your repository, which contains the CI/CD configuration.
In the .gitlab-ci.yml file, you can define:

The scripts you want to run.
Other configuration files and templates you want to include.
Dependencies and caches.
The commands you want to run in sequence and those you want to run in parallel.
The location to deploy your application to.
Whether you want to run the scripts automatically or trigger any of them manually.
The scripts are grouped into jobs, and jobs run as part of a larger pipeline. You can group multiple independent jobs into stages that run in a defined order.

You should organize your jobs in a sequence that suits your application and is in accordance with the tests you wish to perform. To visualize the process, imagine the scripts you add to jobs are the same as CLI commands you run on your computer.

When you add a .gitlab-ci.yml file to your repository, GitLab detects it and an application called GitLab Runner runs the scripts defined in the jobs.
