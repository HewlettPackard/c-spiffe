# Mutually Authenticated TLS (mTLS)

This example shows how to use the C-spiffe library to establish an mTLS connection between two workloads using X.509 SVIDs obtained from the SPIFFE Workload API. 

One workload acts as a client and the other as the server. 

The scenario goes like this:
1. The server starts listening for incoming SPIFFE-compliant mTLS connections.
2. The client establishes an SPIFFE-compliant mTLS connection to the server. 
3. The server starts waiting for a message from the client.
4. The client sends a "Hello server" message and starts waiting for a response.
5. The server reads the client's message, logs it to stdout, and sends a "Hello client" message as the response.
6. The client reads the server's response and then closes the connection.
