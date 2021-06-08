# Minimum CMake required
cmake_minimum_required(VERSION 3.13)

set(CLIENT
    spiffe-tls/client/main.c
)
add_executable(spiffe_tls_client "${CLIENT}")
target_link_libraries(spiffe_tls_client spiffetls)

set(SERVER
    spiffe-tls/server/main.c
)
add_executable(spiffe_tls_server "${SERVER}")
target_link_libraries(spiffe_tls_server spiffetls)
