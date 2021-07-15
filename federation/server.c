#include "c-spiffe/federation/server.h"
#include "c-spiffe/spiffetls/spiffetls.h"
#include "c-spiffe/utils/error.h"
#include "c-spiffe/utils/picohttpparser.h"
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/un.h>

spiffebundle_EndpointInfo *spiffebundle_EndpointInfo_New()
{
    spiffebundle_EndpointInfo *e_info = calloc(1, sizeof(*e_info));
    mtx_init(&e_info->mutex, mtx_plain);
    return e_info;
}

err_t spiffebundle_EndpointInfo_Free(spiffebundle_EndpointInfo *e_info)
{
    if(!e_info) {
        return ERR_NULL;
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
        return ERR_NULL;
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
        return ERR_NULL;
    }
    if(!path) {
        return ERR_BAD_ARGUMENT;
    }
    if(!bundle_source) {
        return ERR_NULL_DATA;
    }
    if(!td.name) {
        return ERR_INVALID_TRUSTDOMAIN;
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
        return ERR_NULL;
    }
    if(!path) {
        return ERR_BAD_ARGUMENT;
    }
    if(!new_source) {
        return ERR_NULL_DATA;
    }
    if(!td.name) {
        return ERR_INVALID_TRUSTDOMAIN;
    }

    mtx_lock(&server->mutex);
    {
        int idx = shgeti(server->bundle_sources, path);
        if(idx < 0) { // not found
            mtx_unlock(&server->mutex);
            return ERR_NOT_FOUND;
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
        return ERR_NULL;
    }
    if(!path) {
        return ERR_BAD_ARGUMENT;
    }

    mtx_lock(&server->mutex);
    {
        int idx = shgeti(server->bundle_sources, path);
        if(idx < 0) { // not found
            mtx_unlock(&server->mutex);
            return ERR_NOT_FOUND;
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
spiffebundle_EndpointInfo *spiffebundle_EndpointServer_AddHttpsWebEndpoint(
    spiffebundle_EndpointServer *server, const char *base_url, X509 **certs,
    EVP_PKEY *priv_key, err_t *error)
{
    if(!server) {
        *error = ERR_NULL;
        return NULL;
    }
    if(!base_url) {
        *error = ERR_BAD_ARGUMENT;
        return NULL;
    }
    if(!certs || !(certs[0])) {
        *error = ERR_CERTIFICATE_VALIDATION;
        return NULL;
    }
    /// TODO: validate non-svid
    priv_key = x509svid_validatePrivateKey(priv_key, certs[0], error);
    if(!priv_key) {
        *error = ERR_PRIVKEY_VALIDATION;
        return NULL;
    }

    mtx_lock(&server->mutex);
    int idx = shgeti(server->endpoints, base_url);
    if(idx >= 0) {
        EVP_PKEY_free(priv_key);
        mtx_unlock(&server->mutex);
        *error = ERR_EXISTS;
        return NULL;
    }

    spiffebundle_EndpointInfo *e_info = spiffebundle_EndpointInfo_New();
    mtx_lock(&e_info->mutex);
    shput(server->endpoints, base_url, e_info);
    e_info->server = server;
    mtx_unlock(&server->mutex);

    // create svid with blank spiffeid for holding the key and certificates
    x509svid_SVID *svid = calloc(1, sizeof *svid);
    for(size_t i = 0, size = arrlenu(certs); i < size; ++i) {
        X509_up_ref(certs[i]);
        arrput(svid->certs, certs[i]);
    }
    svid->private_key = priv_key;

    x509svid_Source *source = x509svid_SourceFromSVID(svid);
    e_info->listen_mode = spiffetls_TLSServerWithRawConfig(source);
    e_info->url = string_new(base_url);
    e_info->threads = NULL;
    mtx_unlock(&e_info->mutex);

    *error = NO_ERROR;
    return e_info;
}

err_t spiffebundle_EndpointServer_SetHttpsWebEndpointAuth(
    spiffebundle_EndpointServer *server, const char *base_url, X509 **certs,
    EVP_PKEY *priv_key)
{
    if(!server) {
        return ERR_NULL;
    }
    if(!base_url) {
        return ERR_BAD_ARGUMENT;
    }
    if(!certs || !(certs[0])) {
        return ERR_CERTIFICATE_VALIDATION;
    }
    err_t error = NO_ERROR;
    /// TODO: validate non-svid
    priv_key = x509svid_validatePrivateKey(priv_key, certs[0], &error);
    if(!priv_key) {
        return ERR_PRIVKEY_VALIDATION;
    }
    mtx_lock(&server->mutex);
    int idx = shgeti(server->endpoints, base_url);
    if(idx < 0) {
        EVP_PKEY_free(priv_key);
        mtx_unlock(&server->mutex);
        return ERR_EXISTS;
    }
    spiffebundle_EndpointInfo *e_info = server->endpoints[idx].value;
    mtx_lock(&e_info->mutex);

    spiffetls_ListenMode_Free(e_info->listen_mode);

    x509svid_SVID *svid = calloc(1, sizeof *svid);
    for(size_t i = 0, size = arrlenu(certs); i < size; ++i) {
        X509_up_ref(certs[i]);
        arrput(svid->certs, certs[i]);
    }
    svid->private_key = priv_key;

    x509svid_Source *source = x509svid_SourceFromSVID(svid);
    e_info->listen_mode = spiffetls_TLSServerWithRawConfig(source);
    mtx_unlock(&e_info->mutex);
    mtx_unlock(&server->mutex);

    return NO_ERROR;
}

// Register a HTTPS_SPIFFE endpoint, for starting with
// spiffebundle_EndpointServer_ServeEndpoint.
spiffebundle_EndpointInfo *spiffebundle_EndpointServer_AddHttpsSpiffeEndpoint(
    spiffebundle_EndpointServer *server, const char *base_url,
    x509svid_Source *svid_source, err_t *error)
{
    if(!server) {
        *error = ERR_NULL;
        return NULL;
    }
    if(!base_url) {
        *error = ERR_BAD_ARGUMENT;
        return NULL;
    }
    if(!svid_source) {
        *error = ERR_NULL_SVID;
        return NULL;
    }
    mtx_lock(&server->mutex);
    int idx = shgeti(server->endpoints, base_url);
    if(idx >= 0) {
        mtx_unlock(&server->mutex);
        *error = ERR_EXISTS;
        return NULL;
    }
    spiffebundle_EndpointInfo *e_info = spiffebundle_EndpointInfo_New();
    e_info->listen_mode = spiffetls_TLSServerWithRawConfig(svid_source);
    e_info->server = server;
    e_info->url = string_new(base_url);
    e_info->threads = NULL;
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
        return ERR_NULL;
    }
    if(!base_url) {
        return ERR_BAD_ARGUMENT;
    }
    if(!svid_source) {
        return ERR_NULL_SVID;
    }
    mtx_lock(&server->mutex);
    int idx = shgeti(server->endpoints, base_url);
    if(idx < 0) {
        mtx_unlock(&server->mutex);
        return ERR_NOT_FOUND;
    }
    spiffebundle_EndpointInfo *e_info = server->endpoints[idx].value;
    mtx_lock(&e_info->mutex);
    e_info->listen_mode = spiffetls_TLSServerWithRawConfig(svid_source);
    mtx_unlock(&e_info->mutex);
    mtx_unlock(&server->mutex);
    return NO_ERROR;
}

// Get info for serving thread.
spiffebundle_EndpointInfo *spiffebundle_EndpointServer_GetEndpointInfo(
    spiffebundle_EndpointServer *server, const char *base_url, err_t *error)
{
    if(!server) {
        *error = ERR_NULL;
        return NULL;
    }
    if(!base_url) {
        *error = ERR_BAD_ARGUMENT;
        return NULL;
    }
    mtx_lock(&server->mutex);
    int idx = shgeti(server->endpoints, base_url);
    if(idx < 0) {
        mtx_unlock(&server->mutex);
        *error = ERR_NOT_FOUND;
        return NULL;
    }
    *error = NO_ERROR;
    spiffebundle_EndpointInfo *ret = server->endpoints[idx].value;
    mtx_unlock(&server->mutex);
    return ret;
}

// Remove endpoint from server.
err_t spiffebundle_EndpointServer_RemoveEndpoint(
    spiffebundle_EndpointServer *server, const char *base_url)
{
    err_t error = NO_ERROR;
    if(!server) {
        return ERR_NULL;
    }
    if(!base_url) {
        return ERR_BAD_ARGUMENT;
    }
    mtx_lock(&server->mutex);
    int idx = shgeti(server->endpoints, base_url);
    if(idx < 0) {
        mtx_unlock(&server->mutex);
        return ERR_NOT_FOUND;
    }
    spiffebundle_EndpointInfo *ret = server->endpoints[idx].value;
    spiffetls_ListenMode_Free(ret->listen_mode);
    util_string_t_Free(ret->url);
    ret->server = NULL;
    shdel(server->endpoints, base_url);
    mtx_unlock(&server->mutex);
    return NO_ERROR;
}

char *HTTP_OK = "HTTP/1.1 200 OK\r\n";
char *HTTP_NOTFOUND = "HTTP/1.1 404 Not Found\r\n";
char *HTTP_METHODNOTALLOWED = "HTTP/1.1 405 Method Not Allowed\r\n";

int serve_function(void *arg)
{
    spiffebundle_EndpointThread *e_thread = arg;
    spiffebundle_EndpointInfo *e_info = e_thread->endpoint_info;
    spiffebundle_EndpointServer *server = e_info->server;
    bool started = false;
    while(e_thread->active) {
        err_t err = NO_ERROR;
        write(e_thread->control_socks[1], "OK!\r\n", 6);
        spiffetls_ListenMode *mode = e_info->listen_mode;
        int timeout = 5000; // msec
        SSL *conn = spiffetls_PollWithMode(
            e_thread->port, mode, &e_thread->config,
            &e_thread->config.listener_fd, e_thread->control_socks[1], timeout,
            &err);

        if(conn == NULL) {
            if(err == NO_ERROR) { /// POLL received signal
                continue;
            }
            /// LOG: printf("spiffetls_PollWithMode() failed(%d)\n", err);
        }

        // handle client
        char buf[4096], *method, *path;
        int pret, minor_version;
        struct phr_header headers[100];
        size_t buflen = 0, prevbuflen = 0, method_len, path_len, num_headers;
        ssize_t rret;

        while(true) {
            // read request
            while((rret = SSL_read(conn, buf + buflen, sizeof(buf) - buflen))
                      == -1
                  && errno == EINTR)
                ;
            if(rret <= 0)
                err = ERR_READING;
            prevbuflen = buflen;
            buflen += rret;
            // parse
            num_headers = sizeof(headers) / sizeof(headers[0]);
            pret = phr_parse_request(buf, buflen, &method, &method_len, &path,
                                     &path_len, &minor_version, headers,
                                     &num_headers, prevbuflen);
            if(pret > 0) {
                break; // success
            } else if(pret == -1) {
                err = ERR_PARSING;
                break;
            }
            if(buflen == sizeof(buf)) {
                err = ERR_TOO_LONG;
                break;
            }
            // get rest of request
        }
        if(err == ERR_PARSING) {
            /// LOG: HTTP parse error
            break;
        } else if(err == ERR_READING) {
            /// LOG: Error reading from socket
            break;
        } else if(err == ERR_TOO_LONG) {
            /// LOG: Request too long, buffer overflow prevented
            break;
        }
        /// LOG: log request @ which level?
        printf("Server received:\n%s\n", buf);

        method[method_len] = '\0';
        path[path_len] = '\0';
        char *http_res = NULL;
        string_t http_header = NULL;
        string_t bundle_string = NULL;
        char end_of_response[] = "\r\n\r\n";

        // LOG: log path

        if(strcmp(method, "GET") != 0) {
            http_res = HTTP_METHODNOTALLOWED;
            http_header = string_new("Content-Type: application/json\r\n\r\n");
            bundle_string = string_new("{}");
        } else {
            mtx_lock(&server->mutex);
            spiffebundle_Source *source = shget(server->bundle_sources, path);
            string_t td_name = shget(server->bundle_tds, path);
            mtx_unlock(&server->mutex);
            spiffeid_TrustDomain td = { .name = td_name };

            if(source) {
                // log info?
                http_res = HTTP_OK;
                http_header
                    = string_new("Content-Type: application/json\r\n\r\n");
                spiffebundle_Bundle *ret_bundle
                    = spiffebundle_Source_GetSpiffeBundleForTrustDomain(
                        source, td, &err);
                bundle_string = spiffebundle_Bundle_Marshal(ret_bundle, &err);
            } else {
                // log warn?
                http_res = HTTP_NOTFOUND;
                http_header
                    = string_new("Content-Type: application/json\r\n\r\n");
                bundle_string = string_new("{}");
            }
        }

        /// LOG: server response, code, time
        SSL_write(conn, http_res, strlen(http_res));
        SSL_write(conn, http_header, strlen(http_header));
        SSL_write(conn, bundle_string, strlen(bundle_string));
        SSL_write(conn, end_of_response, strlen(end_of_response));

        arrfree(http_header);
        arrfree(bundle_string);
        const int fd = SSL_get_fd(conn);
        SSL_shutdown(conn);
        SSL_free(conn);
        close(fd);
    }
    close(e_thread->config.listener_fd);
    return NO_ERROR;
}

// Serve bundles using the set up protocol. Spawns a thread.
err_t spiffebundle_EndpointServer_ServeEndpoint(
    spiffebundle_EndpointServer *server, const char *base_url, uint port)
{
    if(!server) {
        return ERR_NULL;
    }
    if(!base_url) {
        return ERR_BAD_ARGUMENT;
    }
    if(port == 0 || port >= 1 << 16) { // invalid port number
        return ERR_BAD_PORT;
    }
    mtx_lock(&server->mutex);
    {
        int idx = shgeti(server->endpoints, base_url);
        if(idx < 0) { // endpoint not found
            mtx_unlock(&server->mutex);
            return ERR_NOT_FOUND;
        }
        spiffebundle_EndpointInfo *e_info = server->endpoints[idx].value;

        spiffebundle_EndpointThread *e_thread = calloc(1, sizeof(*e_thread));

        e_thread->port = port;
        e_thread->endpoint_info = e_info;
        e_thread->active = true;

        int res = socketpair(AF_UNIX, SOCK_STREAM, 0, e_thread->control_socks);

        e_thread->config.base_TLS_conf = NULL; // noop
        e_thread->config.listener_fd = 0;      // noop

        mtx_lock(&e_info->mutex);

        hmput(e_info->threads, port, e_thread);
        thrd_create(&e_thread->thread, serve_function, e_thread);

        mtx_unlock(&e_info->mutex);
        char buff[20];
        res = read(e_thread->control_socks[0], buff, 6);
    }
    mtx_unlock(&server->mutex);

    return NO_ERROR;
}

// Stop serving from indicated thread. waits for thread to stop
err_t spiffebundle_EndpointServer_StopEndpointThread(
    spiffebundle_EndpointServer *server, const char *base_url, uint port)
{
    if(!server) {
        return ERR_NULL;
    }
    if(!base_url) {
        return ERR_BAD_ARGUMENT;
    }
    if(port == 0 || port >= 1 << 16) { // invalid port number
        return ERR_BAD_PORT;
    }

    mtx_lock(&server->mutex);
    int idx = shgeti(server->endpoints, base_url);
    if(idx < 0) {
        mtx_unlock(&server->mutex);
        return ERR_NOT_FOUND;
    }
    spiffebundle_EndpointInfo *e_info = server->endpoints[idx].value;
    mtx_unlock(&server->mutex);
    mtx_lock(&e_info->mutex);
    int l = hmgeti(e_info->threads, port);
    if(l < 0) {
        mtx_unlock(&e_info->mutex);
        mtx_unlock(&server->mutex);
        return ERR_EXISTS;
    }
    spiffebundle_EndpointThread *e_thread = e_info->threads[l].value;
    e_thread->active = false;
    int res = write(e_thread->control_socks[0], "END\r\n", 6);
    ///LOG: result

    // remove thread from map
    hmdel(e_info->threads, port);
    thrd_t thread = e_thread->thread;
    int fds[2] = { e_thread->control_socks[0], e_thread->control_socks[1] };

    free(e_thread);
    mtx_unlock(&e_info->mutex);

    // waits for thread to stop;
    thrd_join(thread, NULL);
    // close control sockets
    close(fds[0]);
    close(fds[1]);
    return NO_ERROR;
}

// Stops serving from all threads from endpoint. waits for running threads to
// stop
err_t spiffebundle_EndpointServer_StopEndpoint(
    spiffebundle_EndpointServer *server, const char *base_url)
{
    if(!server) {
        return ERR_NULL;
    }
    if(!base_url) {
        return ERR_BAD_ARGUMENT;
    }
    spiffebundle_EndpointThread **threads_to_join = NULL;
    mtx_lock(&server->mutex);
    {
        int idx = shgeti(server->endpoints, base_url);
        if(idx < 0) {
            mtx_unlock(&server->mutex);
            return ERR_NOT_FOUND;
        }
        spiffebundle_EndpointInfo *e_info = server->endpoints[idx].value;
        mtx_lock(&e_info->mutex);

        for(size_t j = 0, size = hmlenu(e_info->threads); j < size; ++j) {
            spiffebundle_EndpointThread *e_thread = e_info->threads[j].value;
            if(e_thread->active) {
                e_thread->active = false;
                int res = write(e_thread->control_socks[0], "END\r\n", 6);
                arrput(threads_to_join, e_thread);
            }
        }
        hmfree(e_info->threads);
        e_info->threads = NULL;
        mtx_unlock(&e_info->mutex);
    }
    mtx_unlock(&server->mutex);
    for(size_t i = 0, size = arrlenu(threads_to_join); i < size; ++i) {
        thrd_join(threads_to_join[i]->thread, NULL);
        int fds[2] = { threads_to_join[i]->control_socks[0],
                       threads_to_join[i]->control_socks[1] };
        free(threads_to_join[i]);
        close(fds[0]);
        close(fds[1]);
    }
    arrfree(threads_to_join);
    return NO_ERROR;
}

// Stops serving from all threads. waits for all running threads to stop
err_t spiffebundle_EndpointServer_Stop(spiffebundle_EndpointServer *server)
{
    if(!server) {
        return ERR_NULL;
    }
    spiffebundle_EndpointThread **threads_to_join = NULL;
    mtx_lock(&server->mutex);
    for(size_t i = 0, size = shlenu(server->endpoints); i < size; ++i) {
        spiffebundle_EndpointInfo *e_info = server->endpoints[i].value;
        mtx_lock(&e_info->mutex);
        for(size_t j = 0, size2 = shlenu(e_info->threads); j < size2; ++j) {
            spiffebundle_EndpointThread *e_thread = e_info->threads[j].value;
            if(e_thread->active) {
                e_thread->active = false;
                int res = write(e_thread->control_socks[0], "END\r\n", 6);
                arrput(threads_to_join, e_thread);
            }
        }
        hmfree(e_info->threads);
        e_info->threads = NULL;
        mtx_unlock(&e_info->mutex);
    }
    mtx_unlock(&server->mutex);
    for(size_t i = 0, size = arrlenu(threads_to_join); i < size; ++i) {
        thrd_join(threads_to_join[i]->thread, NULL);
        int fds[2] = { threads_to_join[i]->control_socks[0],
                       threads_to_join[i]->control_socks[1] };
        free(threads_to_join[i]);
        close(fds[0]);
        close(fds[1]);
    }
    arrfree(threads_to_join);
    return NO_ERROR;
}
