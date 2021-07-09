#include "server.h"

spiffebundle_EndpointServer *spiffebundle_EndpointServer_New()
{
    spiffebundle_EndpointServer *new_server = calloc(1, sizeof(*new_server));

    mtx_init(&new_server->mutex, mtx_plain);
    mtx_lock(&new_server->mutex);
    sh_new_strdup(new_server->serving_threads);
    sh_new_strdup(new_server->bundle_sources);
    mtx_unlock(&new_server->mutex);
    return new_server;
}

err_t spiffebundle_EndpointServer_Free(spiffebundle_EndpointServer *server)
{
    if(!server) {
        return ERROR1;
    }
    mtx_lock(&server->mutex);

    shfree(server->bundle_sources);
    shfree(server->serving_threads);
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
    shput(server->bundle_sources, path, bundle_source);
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
    int idx = shgeti(server->bundle_sources, path);
    if(idx < 0) {
        return ERROR4;
    }

    server->bundle_sources[idx].value = new_source;

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

    int idx = shgeti(server->bundle_sources, path);
    if(idx < 0) {
        return ERROR3;
    }
    shdel(server->bundle_sources, path);

    mtx_unlock(&server->mutex);

    return NO_ERROR;
}
