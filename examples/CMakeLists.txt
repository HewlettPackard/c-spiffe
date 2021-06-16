# Minimum CMake required
cmake_minimum_required(VERSION 3.13)
# spiffe-tls
set(CLIENT_TLS
    spiffe-tls/client/main.c
)
add_executable(spiffe_tls_client "${CLIENT_TLS}")
target_link_libraries(spiffe_tls_client spiffetls)

set(SERVER_TLS
    spiffe-tls/server/main.c
)
add_executable(spiffe_tls_server "${SERVER_TLS}")
target_link_libraries(spiffe_tls_server spiffetls)

# spiffe-jwt
set(CLIENT_JWT
    spiffe-jwt/client/main.c
)
add_executable(spiffe_jwt_client "${CLIENT_JWT}")
target_link_libraries(spiffe_jwt_client spiffetls curl)

set(SERVER_JWT
    spiffe-jwt/server/main.c
)
add_executable(spiffe_jwt_server "${SERVER_JWT}")
target_link_libraries(spiffe_jwt_server spiffetls)