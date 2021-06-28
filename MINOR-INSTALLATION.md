# Minimal Installation

#### Build Dependencies
* gcc (9.3.0-17ubuntu1~20.04)
* make (4.2.1-1.2)
* libtool (2.4.6-14)
* curl (7.68.0-1ubuntu2.5)
* cmake (3.16.3-1ubuntu1)
* libssl-dev (1.1.1f-1ubuntu2.4)
* liburiparser1 (0.9.3-2)
* liburiparser-dev (0.9.3-2)
* protobuf-compiler (3.13.0)
* libprotobuf-dev (3.13.0)
* libjansson-dev (2.12-1build1)
* libcjose-dev (0.6.1+dfsg1-1)
* zlib1g-dev (1.2.11)
* libcurl4-openssl-dev (7.68.0-1ubuntu2.5)
* check (0.10.0-3build2)

### Compile gRPC

In order to create a pure C lib, supporting gRPC, which is a C++ lib, it is necessarty to compile gRPC code together with c-spiffe code. The following steps can be used for compiling gRPC:

* Clone GRPC source

Currently, we are using `GRPC_VERSION=1.34.0`

```bash
git clone --recurse-submodules -b v${GRPC_VERSION} https://github.com/grpc/grpc
```

* Build grpc

```bash
cmake -DgRPC_INSTALL=ON -DgRPC_SSL_PROVIDER=package ../.
make -j${NUM_JOBS} && make install
```

### Compile C-Spiffe library

* Clone C-Spiffe source
```bash
git clone https://github.com/HewlettPackard/c-spiffe.git
```

Once you meet all the requirements, building is straightforward with `CMake`

```bash
mkdir build && cd build
cmake ..
make -j${NUM_JOBS}
```

### Installing

```bash
make install
ldconfig
```
