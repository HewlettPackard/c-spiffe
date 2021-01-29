# c-spiffe

C extension for Spiffe platform.

## Introduction

gRPC C++ examples built with CMake.

## Files

```
.
├── docker
|   ├── spiffe.Dockerfile
|   ├── ci.Dockerfile
|   ├── test.Dockerfile
│   └── grpc.Dockerfile
├── worlkload
|   ├── src
|   │   ├── file1.cc
|   │   ├── file2.cc
|   │   ├── file3.cc
|   │   └── CMakeLists.txt
│   ├── tests
|   │   ├── test1
|   │   ├── test2
|   │   ├── test3
|   │   └── CMakeLists.txt 
│   └── CMakeLists.txt
├── bundle
│   ├── jwtbundle
│   │   ├── src
│   │   │   ├── file1.cc
│   │   │   ├── file2.cc
│   │   │   ├── file3.cc
|   │   │   └── CMakeLists.txt 
│   │   ├── tests
|   │   │   ├── test1
|   │   │   ├── test2
|   │   │   ├── test3
|   │   │   └── CMakeLists.txt 
│   │   └── CMakeLists.txt
│   ├── spiffebundle
│   │   ├── src
│   │   │   ├── file1.cc
│   │   │   ├── file2.cc
│   │   │   ├── file3.cc
|   │   │   └── CMakeLists.txt 
│   │   ├── tests
|   │   │   ├── test1
|   │   │   ├── test2
|   │   │   ├── test3
|   │   │   └── CMakeLists.txt 
│   │   └── CMakeLists.txt
│   ├── x509bundle
│   │   ├── src
│   │   │   ├── file1.cc
│   │   │   ├── file2.cc
│   │   │   ├── file3.cc
|   │   │   └── CMakeLists.txt 
│   │   ├── tests
|   │   │   ├── test1
|   │   │   ├── test2
|   │   │   ├── test3
|   │   │   └── CMakeLists.txt
|   |   └── CMakeLists.txt
│   └── CMakeLists.txt
├── CMakeLists.txt
├── LICENSE.md
├── protos
│   ├── workload.proto
└── README.md
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
