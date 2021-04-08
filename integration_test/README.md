# Integration tests

This folder contains all integration automated tests scripts. They were all implemented using [Behave](https://behave.readthedocs.io/).

## Installing dependencies


### Python 3 and libs

* Install Python 3.8.3
* python -m pip install -r requirements.txt
 
### Spire Server
    * Obtain the latest tarball from the SPIRE downloads page and then extract it into the /opt/spire directory using the following commands:
       $ wget https://github.com/spiffe/spire/releases/download/v0.12.0/spire-0.12.0-linux-x86_64-glibc.tar.gz
       $ tar zvxf spire-0.12.0-linux-x86_64-glibc.tar.gz
       $ sudo cp -r spire-0.12.0/. /opt/spire/
    * add spire-server and spire-agent to your $PATH for convenience:
       $ sudo ln -s /opt/spire/bin/spire-server /usr/bin/spire-server
       $ sudo ln -s /opt/spire/bin/spire-agent /usr/bin/spire-agent
## Starting spire server

       $ spire-server run -config /opt/spire/conf/server/server.conf
## Generating token
       $ spire-server token generate -spiffeID spiffe://example.org/myagent
       $ TOKEN="token_value"
       $ spire-agent run -joinToken $TOKEN -config /opt/spire/conf/agent/agent.conf

**Note**: It is necessary to run all test cases inside the docker container..