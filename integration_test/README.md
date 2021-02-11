* Install Python 3.8.3
* python -m pip install -r requirements.txt
 
INSTALL SPIRE:
    * Obtain the latest tarball from the SPIRE downloads page and then extract it into the /opt/spire directory using the following commands:
       $ wget https://github.com/spiffe/spire/releases/download/v0.12.0/spire-0.12.0-linux-x86_64-glibc.tar.gz
       $ tar zvxf spire-0.12.0-linux-x86_64-glibc.tar.gz
       $ sudo cp -r spire-0.12.0/. /opt/spire/
    * add spire-server and spire-agent to your $PATH for convenience:
       $ sudo ln -s /opt/spire/bin/spire-server /usr/bin/spire-server
       $ sudo ln -s /opt/spire/bin/spire-agent /usr/bin/spire-agent
* UP spire server:
       $ spire-server run -config /opt/spire/conf/server/server.conf
* Generate token:
       $ spire-server token generate -spiffeID spiffe://example.org/myagent
       $ TOKEN="token_value"
       $ spire-agent run -joinToken $TOKEN -config /opt/spire/conf/agent/agent.conf

Note: It is necessary to run all test cases inside the docker container..