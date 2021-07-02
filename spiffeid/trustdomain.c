#include "c-spiffe/spiffeid/trustdomain.h"

spiffeid_TrustDomain spiffeid_TrustDomainFromString(const char *uri,
                                                    err_t *err)
{
    const char spiffe_scheme[] = "spiffe://";
    const size_t spiffe_scheme_len = sizeof spiffe_scheme - 1;

    string_t str = string_new(uri);

    if(!string_contains(str, "://")) {
        // inserts spiffe scheme at beginning of the string
        arrinsn(str, 0, spiffe_scheme_len);
        memcpy(str, spiffe_scheme, spiffe_scheme_len);
    }

    spiffeid_ID id = spiffeid_FromString(str, err);
    arrfree(str);

    if(!(*err)) {
        arrfree(id.path);
    }

    return id.td;
}

spiffeid_TrustDomain spiffeid_TrustDomainFromURI(const UriUriA *uri,
                                                 err_t *err)
{
    spiffeid_ID id = spiffeid_FromURI(uri, err);
    spiffeid_TrustDomain td = { NULL };

    if(!(*err)) {
        arrfree(id.path);
        td = id.td;
    }

    return td;
}

const char *spiffeid_TrustDomain_String(const spiffeid_TrustDomain td)
{
    return td.name;
}

spiffeid_ID spiffeid_TrustDomain_ID(const spiffeid_TrustDomain td)
{
    return (spiffeid_ID){ { string_new(td.name) }, string_new("") };
}

string_t spiffeid_TrustDomain_IDString(const spiffeid_TrustDomain td)
{
    spiffeid_ID id = spiffeid_TrustDomain_ID(td);
    string_t str = spiffeid_ID_String(id);
    spiffeid_ID_Free(&id);

    return str;
}

spiffeid_ID spiffeid_TrustDomain_NewID(const spiffeid_TrustDomain td,
                                       const char *path)
{
    return (spiffeid_ID){ { string_new(td.name) },
                          spiffeid_normalizePath(string_new(path)) };
}

bool spiffeid_TrustDomain_IsZero(const spiffeid_TrustDomain td)
{
    return empty_str(td.name);
}

int spiffeid_TrustDomain_Compare(const spiffeid_TrustDomain td1,
                                 const spiffeid_TrustDomain td2)
{
    return strcmp(td1.name, td2.name);
}

void spiffeid_TrustDomain_Free(spiffeid_TrustDomain *td)
{
    if(td) {
        arrfree(td->name);
    }
}
