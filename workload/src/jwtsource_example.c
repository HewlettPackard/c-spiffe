#include "jwtsource.h"
#include <threads.h>
#include <time.h>

void print_function(jwtbundle_Set *set, void *not_used)
{
    BIO *out;
    out = BIO_new_fd(fileno(stdout), BIO_NOCLOSE);

    for(uint32_t i = 0, size = jwtbundle_Set_Len(set); i < size; ++i) {
        printf("TD name: %s\n", set->bundles[i].value->td.name);

        for(size_t j = 0, size2 = hmlenu(set->bundles[i].value->auths);
            j < size2; ++j) {
            printf(" kID: %s\n", set->bundles[i].value->auths[j].key);
            EVP_PKEY_print_params(out, set->bundles[i].value->auths[j].value,
                                  2, NULL);
            EVP_PKEY_print_public(out, set->bundles[i].value->auths[j].value,
                                  2, NULL);
        }
    }
    BIO_free(out);
}

int print_forever(void *args)
{
    workloadapi_JWTSource *source = (workloadapi_JWTSource *) args;
    struct timespec tp = { 1, 0 };
    err_t err = NO_ERROR;
    jwtsvid_Params *params = (jwtsvid_Params *) calloc(1, sizeof *params);
    while(!workloadapi_JWTSource_checkClosed(source)) {
        jwtsvid_SVID *svid
            = workloadapi_JWTSource_GetJWTSVID(source, params, &err);
        print_function(source->bundles, NULL);
        if(svid) {
            printf("Token:%s\nExpiry:%s\nerr?:%d\n", svid->token,
                   ctime(&svid->expiry), err);
            thrd_sleep(&tp, NULL);
            for(size_t i = 0, size = arrlenu(svid->audience); i < size; ++i) {
                jwtsvid_SVID *svid2 = workloadapi_Client_ValidateJWTSVID(
                    source->watcher->client, svid->token, svid->audience[i],
                    &err);
                printf("Token:%s\nAudience:%s\n,err?:%d\n", svid->token,
                       svid->audience[i], err);

                if(svid2) {
                    printf("Token2:%s\nExpiry:%s\n", svid2->token,
                           ctime(&svid2->expiry));
                }
            }
        } else {
            break;
        }
    }
    return 0;
}

int main()
{
    err_t err = NO_ERROR;
    workloadapi_JWTSource *source = workloadapi_NewJWTSource(NULL, &err);

    if(err) {
        /// TODO: ERRO
    }

    err = workloadapi_JWTSource_Start(source);

    if(err) {
        /// TODO: ERRO
    }
    thrd_t thread;
    thrd_create(&thread, print_forever, source);
    printf("\n\n\nPress ENTER to continue.\n\n\n");
    err = workloadapi_JWTSource_Close(source);

    thrd_join(thread, NULL);
    return 0;
}
