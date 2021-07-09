#include "server.h"
spiffebundle_EndpointServer_EndpointInfo *
spiffebundle_EndpointServer_EndpointInfo_New()
{
    spiffebundle_EndpointServer_EndpointInfo *e_info
        = calloc(1, sizeof(*e_info));
    mtx_init(&e_info->mutex, mtx_plain);
    return e_info;
}

err_t spiffebundle_EndpointServer_EndpointInfo_Free(
    spiffebundle_EndpointServer_EndpointInfo *e_info)
{
    mtx_destroy(&e_info->mutex);
    free(e_info);
    return NO_ERROR;
}

spiffebundle_EndpointServer *spiffebundle_EndpointServer_New()
{
    spiffebundle_EndpointServer *new_server = calloc(1, sizeof(*new_server));

    mtx_init(&new_server->mutex, mtx_plain);
    mtx_lock(&new_server->mutex);
    {
        sh_new_strdup(new_server->endpoints);
        sh_new_strdup(new_server->bundle_sources);
    }
    mtx_unlock(&new_server->mutex);
    return new_server;
}

err_t spiffebundle_EndpointServer_Free(spiffebundle_EndpointServer *server)
{
    if(!server) {
        return ERROR1;
    }

    mtx_lock(&server->mutex);
    {
        shfree(server->bundle_sources);
        shfree(server->endpoints);
    }
    mtx_unlock(&server->mutex);

    mtx_destroy(&server->mutex);
    free(server);
    return NO_ERROR;
}

err_t spiffebundle_EndpointServer_RegisterBundle(
    spiffebundle_EndpointServer *server, const char *path,
    spiffebundle_Source *bundle_source)
{
    if(!server) {
        return ERROR1;
    }
    if(!path) {
        return ERROR2;
    }
    if(!bundle_source) {
        return ERROR3;
    }
    mtx_lock(&server->mutex);
    {
        shput(server->bundle_sources, path, bundle_source);
    }
    mtx_unlock(&server->mutex);

    return NO_ERROR;
}

err_t spiffebundle_EndpointServer_UpdateBundle(
    spiffebundle_EndpointServer *server, const char *path,
    spiffebundle_Source *new_source)
{
    if(!server) {
        return ERROR1;
    }
    if(!path) {
        return ERROR2;
    }
    if(!new_source) {
        return ERROR3;
    }

    mtx_lock(&server->mutex);
    {
        int idx = shgeti(server->bundle_sources, path);
        if(idx < 0) {
            return ERROR4;
        }

        server->bundle_sources[idx].value = new_source;
    }
    mtx_unlock(&server->mutex);
    return NO_ERROR;
}

// removes bundle from server.
err_t spiffebundle_EndpointServer_RemoveBundle(
    spiffebundle_EndpointServer *server, const char *path)
{
    if(!server) {
        return ERROR1;
    }
    if(!path) {
        return ERROR2;
    }

    mtx_lock(&server->mutex);
    {
        int idx = shgeti(server->bundle_sources, path);
        if(idx < 0) {
            return ERROR3;
        }
        shdel(server->bundle_sources, path);
    }
    mtx_unlock(&server->mutex);

    return NO_ERROR;
}

// load keys to use with 'https_web'
// register a HTTPS_WEB endpoint, for starting with
// spiffebundle_EndpointServer_ServeEndpoint
spiffebundle_EndpointServer_EndpointInfo *
spiffebundle_EndpointServer_AddHttpsWebEndpoint(
    spiffebundle_EndpointServer *server, const char *base_url, X509 *cert,
    EVP_PKEY *priv_key, err_t *error)
{
    if(!server) {
        return ERROR1;
    }
    if(!base_url) {
        return ERROR2;
    }
    if(!cert) {
        return ERROR3;
    }
    if(!priv_key) {
        return ERROR4;
    }
    mtx_lock(&server->mutex);
    int idx = shgeti(server->endpoints, base_url);
    if(idx >= 0) {
        mtx_unlock(&server->mutex);
        *error = ERROR4;
        return NULL;
    }
    spiffebundle_EndpointServer_EndpointInfo *e_info
        = spiffebundle_EndpointServer_EndpointInfo_New();
        ///TODO: add listen mode with x509* and EVP_PKEY* params.
    // e_info->listen_mode = spiffetls_TLSServerWithRawConfig(svid_source);
    e_info->server = server;
    e_info->url = string_new(base_url);
    e_info->port = SPIFFE_DEFAULT_HTTPS_PORT;
    shput(server->endpoints, base_url, e_info);
    mtx_unlock(&server->mutex);
    *error = NO_ERROR;
    return e_info;
}

err_t spiffebundle_EndpointServer_SetHttpsWebEndpointAuth(
    spiffebundle_EndpointServer *server, const char *base_url, X509 *cert,
    EVP_PKEY *priv_key);

// Register a HTTPS_SPIFFE endpoint, for starting with
// spiffebundle_EndpointServer_ServeEndpoint.
spiffebundle_EndpointServer_EndpointInfo *
spiffebundle_EndpointServer_AddHttpsSpiffeEndpoint(
    spiffebundle_EndpointServer *server, const char *base_url,
    x509svid_Source *svid_source, err_t *error)
{
    if(!server) {
        *error = ERROR1;
        return NULL;
    }
    if(!base_url) {
        *error = ERROR2;
        return NULL;
    }
    if(!svid_source) {
        *error = ERROR3;
        return NULL;
    }
    mtx_lock(&server->mutex);
    int idx = shgeti(server->endpoints, base_url);
    if(idx >= 0) {
        mtx_unlock(&server->mutex);
        *error = ERROR4;
        return NULL;
    }
    spiffebundle_EndpointServer_EndpointInfo *e_info
        = spiffebundle_EndpointServer_EndpointInfo_New();
    e_info->listen_mode = spiffetls_TLSServerWithRawConfig(svid_source);
    e_info->server = server;
    e_info->url = string_new(base_url);
    e_info->port = SPIFFE_DEFAULT_HTTPS_PORT;
    shput(server->endpoints, base_url, e_info);
    mtx_unlock(&server->mutex);
    *error = NO_ERROR;
    return e_info;
}

err_t spiffebundle_EndpointServer_SetHttpsSpiffeEndpointSource(
    spiffebundle_EndpointServer *server, const char *base_url,
    x509svid_Source *svid_source);

// Get info for serving thread.
spiffebundle_EndpointServer_EndpointInfo *
spiffebundle_EndpointServer_GetEndpointInfo(
    spiffebundle_EndpointServer *server, const char *base_url, err_t *error);

// Remove endpoint from server.
err_t spiffebundle_EndpointServer_RemoveEndpoint(
    spiffebundle_EndpointServer *server, const char *base_url);

// Serve bundles using the set up protocol. Spawns a thread.
err_t spiffebundle_EndpointServer_ServeEndpoint(
    spiffebundle_EndpointServer *server, const char *base_url, uint port);

// Stop serving from indicated thread.
err_t spiffebundle_EndpointServer_StopEndpoint(
    spiffebundle_EndpointServer *server, const char *base_url);

// Stops serving from all threads.
err_t spiffebundle_EndpointServer_StopAll(spiffebundle_EndpointServer *server);

int serve_function_HTTPS_SPIFFE(void *arg)
{
    spiffebundle_EndpointServer_EndpointInfo *t_info = arg;
    spiffebundle_EndpointServer *server = t_info->server;
    spiffetls_ListenMode *mode = server->listen_mode;
    spiffetls_listenConfig config
        = { .base_TLS_conf = NULL, .listener_fd = 0 };
    err_t err = NO_ERROR;
    t_info->active = true;
    int sock_fd;
    while(t_info->active) {
        SSL *conn = spiffetls_ListenWithMode(t_info->port, mode, &config,
                                             &sock_fd, &err);

        if(conn == NULL) {
            printf("spiffetls_ListenWithMode() failed\n");
            exit(-1);
        }
        if(err != NO_ERROR) {
            printf("could not create TLS connection!");
            exit(-1);
        }

        char buff[1024];
        const int bytes = SSL_read(conn, buff, sizeof(buff));
        buff[bytes] = 0;
        // HANDLE HTTP REQUEST
        printf("Server received: %s\n", buff);

        // respond with a bundle (or not)
        string_t *path;
        spiffebundle_Bundle *ret_bundle = shget(server->bundle_sources, path);
        string_t resp = NULL;
        if(ret_bundle) {
            resp = spiffebundle_Bundle_Marshal(ret_bundle, &err);
        } else {
            resp = string_new("404 - Not Found.");
        }
        SSL_write(conn, resp, strlen(resp));
        /// LOG:
        // printf("Server replied: %s\n", resp);

        const int fd = SSL_get_fd(conn);
        SSL_shutdown(conn);
        SSL_free(conn);
        close(fd);
        // close(sock_fd); //reuse listen
    }

    spiffetls_ListenMode_Free(mode);

    return 1;
}

// Serve bundles using the 'https_spiffe' protocol. Spawns a thread. Returns an
// id that can be used to stop serving from this thread.
err_t spiffebundle_EndpointServer_ServeHTTPSSpiffe(
    spiffebundle_EndpointServer *server, const char *base_url, uint port)
{
    if(!server) {
        return ERROR1;
    }
    if(!base_url) {
        return ERROR2;
    }
    if(port == 0 || port > 65535) {
        return ERROR3;
    }
    int id;
    mtx_lock(&server->mutex);
    {
        spiffebundle_EndpointServer_EndpointInfo *t_info
            = calloc(1, sizeof(*t_info));
        t_info->thread = calloc(1, sizeof(thrd_t));
        t_info->port = port;
        t_info->server = server;
        t_info->url = string_new(base_url);
        shput(server->endpoints, t_info->url, t_info);
        thrd_create(t_info->thread, serve_function_HTTPS_SPIFFE, t_info);
    }
    mtx_unlock(&server->mutex);

    return NO_ERROR;
}
