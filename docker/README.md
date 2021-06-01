# Docker

This folder contains the Dockerfile for the GRPC build environment. 

## Building image 

You can build the docker image from source with the above command line:

```
docker build -f docker/grpc.Dockerfile --build-arg GPRC_VERSION=1.34.0 --build-arg NUM_JOBS=8 --tag grpc-build:1.34.0 .
```

This image is also available on Dockerhub as `cspiffe/grpc-build:1.34.0`
