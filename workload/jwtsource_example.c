#include "c-spiffe/workload/jwtsource.h"
#include "c-spiffe/svid/jwtsvid/parse.h"
#include <threads.h>
#include <time.h>

int print_forever(void *args)
{
    workloadapi_JWTSource *source = (workloadapi_JWTSource *) args;
    err_t err = NO_ERROR;

    while(!workloadapi_JWTSource_checkClosed(source)) {
        spiffeid_ID id = { NULL, NULL };
        string_t audience = string_new("example.org");
        string_arr_t extra = NULL;
        string_t audience2 = string_new("example2.org");
        arrput(extra, audience2);
        string_t audience3 = string_new("example3.org");
        arrput(extra, audience3);
        jwtsvid_Params params = { .audience = audience,
                                  .extra_audiences = extra,
                                  .subject = id };
        jwtsvid_SVID *svid
            = workloadapi_JWTSource_GetJWTSVID(source, &params, &err);

        util_string_t_Free(audience);
        util_string_t_Free(audience2);
        util_string_t_Free(audience3);

        if(svid) {
            printf("SVID: %s%s\n", svid->id.td.name, svid->id.path);
            printf(" Path: %s\n", svid->id.path);
            printf(" Trust Domain: %s\n", svid->id.td.name);
            printf(" Token: %s\n", svid->token);
            printf(" Expiry:%s", ctime(&svid->expiry));
            printf(" Claims: [\n");

            for(size_t j = 0, size = shlenu(svid->claims); j < size; ++j) {
                char *value
                    = json_dumps(svid->claims[j].value, JSON_ENCODE_ANY);
                printf("  '%s':'%s'\n", svid->claims[j].key, value);
                free(value);
            }
            printf(" ]\n");
            jwtbundle_Set_Print(source->bundles);
            jwtbundle_Source *src = jwtbundle_SourceFromSet(
                jwtbundle_Set_Clone(source->bundles));
            jwtsvid_SVID *svid2 = jwtsvid_ParseAndValidate(
                svid->token, src, svid->audience, &err);

            if(svid2) {
                printf("  Validated SVID: \n");
                printf("   SVID Path: %s\n", svid2->id.path);
                printf("   Trust Domain: %s\n", svid2->id.td.name);
                printf("   Token: %s\n", svid2->token);
                printf("   Expiry:%s", ctime(&svid->expiry));
                printf("   Claims: [\n");
                for(size_t j = 0, size = shlenu(svid2->claims); j < size;
                    ++j) {
                    char *value
                        = json_dumps(svid2->claims[j].value, JSON_ENCODE_ANY);
                    printf("    key: %s, value: %s\n", svid2->claims[j].key,
                           value);
                    free(value);
                }
                printf("   ]\n");
                jwtsvid_SVID_Free(svid2);
            } else {
                printf("  COULDN'T VALIDATE SVID!\n");
            }

            jwtsvid_SVID_Free(svid);
            jwtbundle_Source_Free(src);
            printf("\n\n\nPress ENTER to stop.\n\n\n");
            struct timespec tp = { 5, 0 }; // 5 seconds
            thrd_sleep(&tp, NULL);
        } else {
            printf(" COULDN'T FETCH SVID!\n");
        }
    }
    return 0;
}

int main()
{
    err_t err = NO_ERROR;
    workloadapi_JWTSource *source = workloadapi_NewJWTSource(NULL, &err);

    if(err) {
        printf("ERROR %d\n", err);
        return err;
    }
    printf("\n\n\nPress ENTER to stop.\n\n\n");

    err = workloadapi_JWTSource_Start(source);

    if(err) {
        printf("ERROR %d\n", err);
        return err;
    }

    thrd_t thread;
    thrd_create(&thread, print_forever, source);

    char ch;
    scanf("%c", &ch);

    printf("Stopping.\n");

    err = workloadapi_JWTSource_Close(source);

    if(err != 1) { // error 1 == client closed properly
        printf("ERROR %d\n", err);
        return err;
    }

    thrd_join(thread, NULL);
    workloadapi_JWTSource_Free(source);
    return 0;
}
