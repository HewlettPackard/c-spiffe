#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include "../include/id.h"
#include "../include/trustdomain.h"
#include "../../utils/include/stb_ds.h"

static string_t join(const string_arr_t str_arr)
{
    string_t res_str = NULL;
    const size_t arr_size = arrlenu(str_arr);
    size_t tot_len = 0;
    size_t *len_arr = NULL;

    for(size_t i = 0; i < arr_size; ++i)
    {   
        // tot_len += arrlenu(str_arr[i]) - 1;
        const size_t len = strlen(str_arr[i]);
        arrpush(len_arr, len);
        tot_len += len;
    }

    arrsetcap(res_str, tot_len + 1);
    string_t curr_str = res_str;

    for(size_t i = 0; i < arr_size; ++i)
    {
        // size_t temp_size = arrlenu(str_arr[i]);
        // temp_size = temp_size > 0? temp_size - 1 : 0;
        // size_t temp_size = strlen(str_arr[i]);

        // const size_t temp_size = len_arr[i];
        strcpy(curr_str, str_arr[i]);
        curr_str += len_arr[i];
    }

    arrfree(len_arr);
    // curr_str[0] = '\0';

    return res_str;
}

string_t spiffeid_normalizePath(string_t str)
{
    if(arrlenu(str) > 0 && str[0] != '/')
    {
        //inserts '/' at the beginning
        arrins(str, 0, '/');
    }

    return str;
}

string_t spiffeid_Join(string_t td_str, 
                            const string_arr_t segments, err_t *err)
{
    err_t err2;
    const spiffeid_ID id = spiffeid_ID_New(td_str, segments, &err2);

    if(!err2)
    {
        *err = NO_ERROR;
        return spiffeid_ID_String(id);
    }
    else
    {
        *err = err2;
        return NULL;
    }
}

static URL_t URL_parse(const string_t str, err_t *err)
{
    URL_t uri;
    return uri;
}

static void tolower_str(string_t str)
{
    for(; *str; ++str) *str = tolower(*str);
}

void spiffeid_normalizeTrustDomain(string_t str)
{
    tolower_str(str);
}

spiffeid_ID spiffeid_FromURI(const URL_t *uri, err_t *err)
{
    spiffeid_ID id = {NULL, NULL};

    if(!uri)
    {
        *err = ERROR1;
        return id;
    }
    else if(empty_str(uri->host))    //empty trust domain
    {
        *err = ERROR1;
        return id;
    }
    else if(empty_str(uri->path))    //empty path
    {
        *err = ERROR1;
        return id;
    }
    else if(empty_str(uri->scheme))  //empty scheme
    {
        *err = ERROR1;
        return id;
    }
    else if(strcmp(uri->scheme, "scheme")) //invalid scheme
    {
        *err = ERROR1;
        return id;
    }
    else if(!empty_str(uri->user)) //user info
    {
        *err = ERROR1;
        return id;
    } 
    else if(!empty_str(uri->port)) //port info
    {
        *err = ERROR1;
        return id;
    }
    else if(false) //using colon
    {

    }
    else if(!empty_str(uri->fragment))  //fragment info
    {
        *err = ERROR1;
        return id;
    }    
    else if(!empty_str(uri->raw_query)) //query info
    {
        *err = ERROR1;
        return id;
    }

    // arrsetcap(id.td.name, arrlenu(uri->host));
    // arrsetcap(id.td.name, strlen(uri->host) + 1);
    // strcpy(id.td.name, uri->host);
    id.td.name = string_push(id.td.name, uri->host);
    spiffeid_normalizeTrustDomain(id.td.name);

    // arrsetcap(id.path, arrlenu(uri->path));
    // arrsetcap(id.path, strlen(uri->path) + 1);
    // strcpy(id.path, uri->path);
    id.path = string_push(id.path, uri->path);

    return id;
}

spiffeid_ID spiffeid_ID_New(const string_t td_str, 
                            const string_arr_t segments, err_t *err)
{
    spiffeid_ID id = {NULL, NULL};
    err_t err2;

    spiffeid_TrustDomain td = spiffeid_TrustDomainFromString(td_str, &err2);
    
    if(!err2)
    {
        id.td = td;
        id.path = spiffeid_normalizePath(join(segments));
        
        *err = NO_ERROR;
        return id;
    }
    else
    {
        *err = err2;
        return id;
    }
}

spiffeid_ID spiffeid_FromString(const string_t str, err_t *err)
{
    spiffeid_ID id = {NULL, NULL};
    err_t err2;
    URL_t uri = URL_parse(str, &err2);

    if(!err2)
    {
        id = spiffeid_FromURI(&uri, &err2);
        util_URL_t_Free(&uri, false);
        *err = err2;
        return id;
    }
    else
    {
        util_URL_t_Free(&uri, false);
        *err = err2;
        return id;
    }
    
}

void spiffeid_ID_Free(spiffeid_ID *id, bool alloc)
{
    if(id)
    {
        arrfree(id->td.name);
        arrfree(id->path);
        if(alloc)
            free(id);
    }
}

#if !__SPIFFE_ID_BY_POINTER__

spiffeid_TrustDomain spiffeid_ID_TrustDomain(const spiffeid_ID id)
{
    return id.td;
}

bool spiffeid_ID_MemberOf(const spiffeid_ID id, const spiffeid_TrustDomain td)
{
    return !strcmp(id.td.name, td.name);
}

const string_t spiffeid_ID_Path(const spiffeid_ID id)
{
    return id.path;
}

static string_t URL_to_string(const URL_t *url);

string_t spiffeid_ID_String(const spiffeid_ID id)
{
    URL_t uri = spiffeid_ID_URL(id);
    string_t str = URL_to_string(&uri);
    util_URL_t_Free(&uri, false);

    return str;
}

URL_t spiffeid_ID_URL(const spiffeid_ID id)
{
    URL_t uri;
    memset(&uri, NULL, sizeof(URL_t));

    uri.scheme = string_push(uri.scheme, "spiffe");
    uri.host = string_push(uri.host, id.td.name);
    uri.path = string_push(uri.path, id.path);

    return uri;
}

bool spiffeid_ID_IsZero(const spiffeid_ID id)
{
#if !__TRUSTDOMAIN_BY_POINTER__
    return spiffeid_TrustDomain_IsZero(id.td);
#endif
}

#else

spiffeid_TrustDomain spiffeid_ID_TrustDomain(const spiffeid_ID *id)
{
    return id->td;
}

bool spiffeid_ID_MemberOf(const spiffeid_ID *id, const spiffeid_TrustDomain *td)
{
    return !strcmp(id->td.name, td->name);
}

const string_t spiffeid_ID_Path(const spiffeid_ID *id)
{
    return id->path;
}

static string_t URL_to_string(const URL_t *url);

string_t spiffeid_ID_String(const spiffeid_ID *id)
{
    URL_t uri = spiffeid_ID_URL(id);
    string_t str = URL_to_string(&uri);
    util_URL_t_Free(&uri, false);

    return str;
}

URL_t spiffeid_ID_URL(const spiffeid_ID *id)
{
    URL_t uri;
    memset(&uri, NULL, sizeof(URL_t));

    uri.scheme = string_push(uri.scheme, "spiffe");
    uri.host = string_push(uri.host, id->td.name);
    uri.path = string_push(uri.path, id->path);

    return uri;
}

#endif
