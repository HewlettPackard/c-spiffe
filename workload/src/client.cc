#include "client.h"
#include "../../internal/x509util/src/util.h"

x509bundle_Set* workloadapi_parseX509Bundles(const X509SVIDResponse *rep, err_t *err)
{
    if(rep)
    {
        x509bundle_Set *set = x509bundle_NewSet(0);

        auto ids = rep->svids();
        for(auto &&id : ids)
        {
            err_t err;
            string_t td_str = string_new(id.spiffe_id().c_str());
            x509bundle_Bundle *b = workloadapi_parseX509Bundle(
                            td_str,
                            reinterpret_cast<const byte*>(id.bundle().data()),
                            id.bundle().length(),
                            &err);
            arrfree(td_str);
            x509bundle_Set_Add(set, b);
        }

        auto map_td_bytes = rep->federated_bundles();
        for(auto const& td_byte : map_td_bytes)
        {
            err_t err;
            string_t td_str = string_new(td_byte.first.c_str());
            x509bundle_Bundle *b = workloadapi_parseX509Bundle(
                            td_str,
                            reinterpret_cast<const byte*>(td_byte.second.data()),
                            td_byte.second.length(),
                            &err);
            arrfree(td_str);
            x509bundle_Set_Add(set, b);
        }
    
        return set;
    }
    //null pointer error
    *err = ERROR1;
    return NULL;
}

x509bundle_Bundle* workloadapi_parseX509Bundle(string_t id, const byte *bundle_bytes, const size_t len, err_t *err)
{
    x509bundle_Bundle *bundle = NULL;

    if(id && bundle_bytes)
    {
        spiffeid_TrustDomain td = spiffeid_TrustDomainFromString(id, err);

        if(!(*err))
        {
            X509 **certs = x509util_ParseCertificates(bundle_bytes, len, err);

            if(!(*err) && arrlenu(certs) > 0)
            {
                bundle = x509bundle_FromX509Authorities(td, certs);   
            }
        }

        spiffeid_TrustDomain_Free(&td, false);
    }

    return bundle;
}
