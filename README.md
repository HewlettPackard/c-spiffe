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
│   ├── test
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
│   │   ├── test
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
│   │   ├── test
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
│   │   ├── test
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
docker build -f docker/grpc.Dockerfile --build-arg GPRC_VERSION=1.34.0 --build-arg NUM_JOBS=8 --tag c-spiffe:1.34.0 .
```

## Run Docker Container

```
docker run -it --rm --network host -v $(pwd):/mnt c-spiffe:1.34.0
```

## Building
Build the c-spiffe project:

```bash
cmake -B build
cmake --build build --config Release --parallel
```
