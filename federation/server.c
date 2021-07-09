#include "server.h"

spiffebundle_EndpointServer *spiffebundle_EndpointServer_New()
{
    spiffebundle_EndpointServer *new_server = calloc(1, sizeof(*new_server));

    mtx_init(&new_server->mutex, mtx_plain);
    mtx_lock(&new_server->mutex);
    {
        sh_new_strdup(new_server->serving_threads);
        /// TODO: check this
        // sh_new_strdup(new_server->bundle_sources);
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
        shfree(server->serving_threads);
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

// register a X509 SVID source for use with 'https_web'
err_t spiffebundle_EndpointServer_RegisterSVIDSource(
    spiffebundle_EndpointServer *server, x509svid_Source *svid_source)
{
    if(!server) {
        return ERROR1;
    }
    if(!svid_source) {
        return ERROR2;
    }

    mtx_lock(&server->mutex);
    {
        server->svid_source = svid_source;
    }
    mtx_unlock(&server->mutex);

    return NO_ERROR;
}

// remove SVID source.
err_t spiffebundle_EndpointServer_ClearSVIDSource(
    spiffebundle_EndpointServer *server)
{
    if(!server) {
        return ERROR1;
    }
    if(!server->svid_source) {
        /// TODO: error on already clear?
        return NO_ERROR;
    }

    mtx_lock(&server->mutex);
    {
        server->svid_source = NULL;
    }
    mtx_unlock(&server->mutex);

    return NO_ERROR;
}

int serve_function(void *arg)
{
    server_thread_info *t_info = arg;

    return 1;
}

// Serve bundles using the 'https_spiffe' protocol. Spawns a thread. Returns an
// id that can be used to stop serving from this thread.
int spiffebundle_EndpointServer_ServeHTTPSSpiffe(
    spiffebundle_EndpointServer *server, const char *base_url, uint port,
    err_t *error)
{
    if(!server) {
        *error = ERROR1;
        return 0;
    }
    if(!base_url) {
        *error = ERROR2;
        return 0;
    }
    if(port == 0 || port > 65535) {
        *error = ERROR3;
        return 0;
    }
    mtx_lock(&server->mutex);
    {
        server_thread_info *t_info = calloc(1, sizeof(*t_info));
        t_info->thread = calloc(1, sizeof(thrd_t));
        t_info->port = port;
        t_info->server = server;
        t_info->url = base_url;
        /// TODO: this isn't an ID. create id.
        int id = thrd_create(t_info->thread, serve_function, t_info);

        hmput(server->serving_threads, id, t_info);
    }
    mtx_unlock(&server->mutex);
    *error = NO_ERROR;
    return 0;
}
