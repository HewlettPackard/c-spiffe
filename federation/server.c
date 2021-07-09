#include "server.h"
#include "utils/picohttpparser.h"
#include <errno.h>
#include <stdio.h>

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
    if(!e_info) {
        return ERROR1;
    }
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
        sh_new_strdup(new_server->bundle_tds);
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
        shfree(server->bundle_tds);
    }
    mtx_unlock(&server->mutex);

    mtx_destroy(&server->mutex);
    free(server);
    return NO_ERROR;
}

err_t spiffebundle_EndpointServer_RegisterBundle(
    spiffebundle_EndpointServer *server, const char *path,
    spiffebundle_Source *bundle_source, spiffeid_TrustDomain td)
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
    if(!td.name) {
        return ERROR4;
    }

    mtx_lock(&server->mutex);
    {
        shput(server->bundle_sources, path, bundle_source);
        shput(server->bundle_tds, path, string_new(td.name));
    }
    mtx_unlock(&server->mutex);

    return NO_ERROR;
}

err_t spiffebundle_EndpointServer_UpdateBundle(
    spiffebundle_EndpointServer *server, const char *path,
    spiffebundle_Source *new_source, spiffeid_TrustDomain td)
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
        if(idx < 0) { // not found
            mtx_unlock(&server->mutex);
            return ERROR4;
        }
        server->bundle_sources[idx].value = new_source;
        if(server->bundle_tds[idx].value) {
            arrfree(server->bundle_tds[idx].value);
        }
        server->bundle_tds[idx].value = string_new(td.name);
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
        if(idx < 0) { // not found
            mtx_unlock(&server->mutex);
            return ERROR3;
        }

        // free string from td strings map
        arrfree(server->bundle_tds[idx].value);

        shdel(server->bundle_sources, path);
        shdel(server->bundle_tds, path);
    }
    mtx_unlock(&server->mutex);

    return NO_ERROR;
}

// load keys to use with 'https_web'
// register a HTTPS_WEB endpoint, for starting with
// spiffebundle_EndpointServer_ServeEndpoint
spiffebundle_EndpointServer_EndpointInfo *
spiffebundle_EndpointServer_AddHttpsWebEndpoint(
    spiffebundle_EndpointServer *server, const char *base_url, X509 **certs,
    EVP_PKEY *priv_key, err_t *error)
{
    if(!server) {
        *error = ERROR1;
        return NULL;
    }
    if(!base_url) {
        *error = ERROR2;
        return NULL;
    }
    if(!certs || !(certs[0])) {
        *error = ERROR3;
        return NULL;
    }
    x509svid_validateSigningCertificates(certs, error);
    if(error != NO_ERROR) {
        *error = ERROR3;
        return NULL;
    }
    priv_key = x509svid_validatePrivateKey(priv_key, certs[0], error);
    if(!priv_key) {
        *error = ERROR4;
        return NULL;
    }
    spiffebundle_EndpointServer_EndpointInfo *e_info
        = spiffebundle_EndpointServer_EndpointInfo_New();

    mtx_lock(&e_info->mutex);
    { // create svid with blank spiffeid for holding the key and certificates
        x509svid_SVID *svid = calloc(1, sizeof *svid);
        x509svid_Source *source = x509svid_SourceFromSVID(svid);
        for(size_t i = 0, size = arrlenu(certs); i < size; ++i) {
            X509_up_ref(certs[i]);
            arrput(svid->certs, certs[i]);
        }
        svid->private_key = priv_key;
        
        e_info->listen_mode = spiffetls_TLSServerWithRawConfig(svid);
        e_info->url = string_new(base_url);
        e_info->port = SPIFFE_DEFAULT_HTTPS_PORT;
    }
    mtx_unlock(&e_info->mutex);

    mtx_lock(&server->mutex);
    {
        int idx = shgeti(server->endpoints, base_url);
        if(idx >= 0) {
            mtx_unlock(&server->mutex);
            *error = ERROR5;
            return NULL;
        }
        e_info->server = server;
        shput(server->endpoints, base_url, e_info);
    }
    mtx_unlock(&server->mutex);
    *error = NO_ERROR;
    return e_info;
}

err_t spiffebundle_EndpointServer_SetHttpsWebEndpointAuth(
    spiffebundle_EndpointServer *server, const char *base_url, X509 **certs,
    EVP_PKEY *priv_key)
{
    if(!server) {
        return ERROR1;
    }
    if(!base_url) {
        return ERROR2;
    }
    if(!certs) {
        return ERROR3;
    }
    if(!priv_key) {
        return ERROR4;
    }
    mtx_lock(&server->mutex);
    int idx = shgeti(server->endpoints, base_url);
    if(idx < 0) {
        mtx_unlock(&server->mutex);
        return ERROR5;
    }
    spiffebundle_EndpointServer_EndpointInfo *e_info
        = server->endpoints[idx].value;
    mtx_lock(&e_info->mutex);
    /// TODO: set listen mode with x509* and EVP_PKEY* params.
    // e_info->listen_mode = spiffetls_TLSServerWithRawConfig(X509**
    // certs,EVP_PKEY *priv_key);
    mtx_unlock(&e_info->mutex);
    mtx_unlock(&server->mutex);

    return NO_ERROR;
}

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
    x509svid_Source *svid_source)
{
    err_t error = NO_ERROR;
    if(!server) {
        return ERROR1;
    }
    if(!base_url) {
        return ERROR2;
    }
    if(!svid_source) {
        return ERROR3;
    }
    mtx_lock(&server->mutex);
    int idx = shgeti(server->endpoints, base_url);
    if(idx < 0) {
        mtx_unlock(&server->mutex);
        return ERROR4;
    }
    spiffebundle_EndpointServer_EndpointInfo *e_info
        = server->endpoints[idx].value;
    mtx_lock(&e_info->mutex);
    e_info->listen_mode = spiffetls_TLSServerWithRawConfig(svid_source);
    mtx_unlock(&e_info->mutex);
    mtx_unlock(&server->mutex);
    return NO_ERROR;
}

// Get info for serving thread.
spiffebundle_EndpointServer_EndpointInfo *
spiffebundle_EndpointServer_GetEndpointInfo(
    spiffebundle_EndpointServer *server, const char *base_url, err_t *error)
{
    if(!server) {
        *error = ERROR1;
        return NULL;
    }
    if(!base_url) {
        *error = ERROR2;
        return NULL;
    }
    mtx_lock(&server->mutex);
    int idx = shgeti(server->endpoints, base_url);
    if(idx < 0) {
        mtx_unlock(&server->mutex);
        *error = ERROR3;
        return NULL;
    }
    *error = NO_ERROR;
    spiffebundle_EndpointServer_EndpointInfo *ret
        = server->endpoints[idx].value;
    mtx_unlock(&server->mutex);
    return ret;
}

// Remove endpoint from server.
err_t spiffebundle_EndpointServer_RemoveEndpoint(
    spiffebundle_EndpointServer *server, const char *base_url)
{
    err_t error = NO_ERROR;
    if(!server) {
        return ERROR1;
    }
    if(!base_url) {
        return ERROR2;
    }
    mtx_lock(&server->mutex);
    int idx = shgeti(server->endpoints, base_url);
    if(idx < 0) {
        mtx_unlock(&server->mutex);
        return ERROR3;
    }
    spiffebundle_EndpointServer_EndpointInfo *ret
        = server->endpoints[idx].value;
    spiffetls_ListenMode_Free(ret->listen_mode);
    util_string_t_Free(ret->url);
    ret->server = NULL;
    shdel(server->endpoints, base_url);
    mtx_unlock(&server->mutex);
    return NO_ERROR;
}

int serve_function(void *arg)
{
    spiffebundle_EndpointServer_EndpointInfo *t_info = arg;
    spiffebundle_EndpointServer *server = t_info->server;
    spiffetls_ListenMode *mode = t_info->listen_mode;
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

        // HANDLE HTTP REQUEST (modified from picohttpparser example)
        char buf[4096], *method, *path; /// TODO: change buffer size?
        int pret, minor_version;
        struct phr_header headers[100];
        size_t buflen = 0, prevbuflen = 0, method_len, path_len, num_headers;
        ssize_t rret;

        while(1) {
            /* read the request */
            while((rret = SSL_read(conn, buf + buflen, sizeof(buf) - buflen))
                      == -1
                  && errno == EINTR)
                ;
            if(rret <= 0)
                return ERROR4;
            prevbuflen = buflen;
            buflen += rret;
            /* parse the request */
            num_headers = sizeof(headers) / sizeof(headers[0]);
            pret = phr_parse_request(buf, buflen, &method, &method_len, &path,
                                     &path_len, &minor_version, headers,
                                     &num_headers, prevbuflen);
            if(pret > 0)
                break; /* successfully parsed the request */
            else if(pret == -1)
                return ERROR5;
            /* request is incomplete, continue the loop */
            if(buflen == sizeof(buf))
                return ERROR6;
        }

        if(strcmp(method, "GET") != 0) {
            /// LOG: not a get request
        }
        /// LOG: log request @ which level?
        printf("Server received: %s\n", buf);

        // respond with a bundle (or not)
        /// LOG: log path
        spiffebundle_Source *source = shget(server->bundle_sources, path);
        string_t td_name = shget(server->bundle_tds, path);
        spiffeid_TrustDomain td = { .name = td_name };
        string_t http_resp = NULL;
        string_t bundle_string = NULL;
        char end_of_response[] = "\n\n";
        if(source) {
            http_resp = string_new("HTTP/1.1 200 OK\n"
                                   "Content-Type: application/json\n\n");
            spiffebundle_Bundle *ret_bundle
                = spiffebundle_Source_GetSpiffeBundleForTrustDomain(source, td,
                                                                    &err);
            bundle_string = spiffebundle_Bundle_Marshal(ret_bundle, &err);
        } else {
            http_resp = string_new("HTTP/1.1 404 Not Found\n"
                                   "Content-Type: application/json\n\n");
            bundle_string = string_new("{}");
        }

        SSL_write(conn, http_resp, strlen(http_resp));
        SSL_write(conn, bundle_string, strlen(bundle_string));
        SSL_write(conn, end_of_response, strlen(end_of_response));

        /// LOG: server response, code, time

        const int fd = SSL_get_fd(conn);
        SSL_shutdown(conn);
        SSL_free(conn);
        close(fd);
    }
    return NO_ERROR;
}

// Serve bundles using the set up protocol. Spawns a thread.
err_t spiffebundle_EndpointServer_ServeEndpoint(
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
    mtx_lock(&server->mutex);
    {
        int idx = shgeti(server->endpoints, base_url);
        if(idx < 0) {
            mtx_unlock(&server->mutex);
            return ERROR4;
        }
        spiffebundle_EndpointServer_EndpointInfo *t_info
            = server->endpoints[idx].value;
        t_info->port = port;
        thrd_create(&t_info->thread, serve_function, t_info);
    }
    mtx_unlock(&server->mutex);

    return NO_ERROR;
}

// Stop serving from indicated thread. waits for thread to stop
err_t spiffebundle_EndpointServer_StopEndpoint(
    spiffebundle_EndpointServer *server, const char *base_url)
{
    if(!server) {
        return ERROR1;
    }
    mtx_lock(&server->mutex);
    {
        int idx = shgeti(server->endpoints, base_url);
        if(idx < 0) {
            mtx_unlock(&server->mutex);
            return ERROR4;
        }
        spiffebundle_EndpointServer_EndpointInfo *t_info
            = server->endpoints[idx].value;
        t_info->active = false;
        // waits for thread to stop;
        thrd_join(&t_info->thread, NULL);
    }
    mtx_unlock(&server->mutex);
    return NO_ERROR;
}

// Stops serving from all threads. waits for all running threads to stop
err_t spiffebundle_EndpointServer_StopAll(spiffebundle_EndpointServer *server)
{
    if(!server) {
        return ERROR1;
    }
    mtx_lock(&server->mutex);
    spiffebundle_EndpointServer_EndpointInfo **threads_to_join = NULL;
    for(size_t i = 0, size = shlenu(server->endpoints); i < size; ++i) {
        if(server->endpoints[i].value->active) {
            server->endpoints[i].value->active = false;
            arrput(threads_to_join, server->endpoints[i].value);
        }
    }
    mtx_unlock(&server->mutex);
    for(size_t i = 0, size = arrlenu(threads_to_join); i < size; ++i) {
        thrd_join(threads_to_join[i]->thread, NULL);
    }
    arrfree(threads_to_join);
    return NO_ERROR;
}
