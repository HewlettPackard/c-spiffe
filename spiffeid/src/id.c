#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include "../include/id.h"
#include "../include/trustdomain.h"
#include "../../utils/include/stb_ds.h"

/*
 * TODO: check return values in spiffeid_FromURI
 */

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
    //null check
    if(str)
    {
        if(arrlenu(str) > 0 && str[0] != '/')
        {
            //inserts '/' at the beginning
            arrins(str, 0, '/');
        }
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

static CURLU* URL_parse(const string_t str, err_t *err)
{
    CURLU *uri = curl_url();
    CURLUcode rc = curl_url_set(uri, CURLUPART_URL, str, 0);

    if(!rc)
    {
        *err = NO_ERROR;
        return uri;    
    }

    *err = ERROR1;
    curl_url_cleanup(uri);
    return NULL;
}

static void tolower_str(string_t str)
{
    for(; *str; ++str) *str = tolower(*str);
}

void spiffeid_normalizeTrustDomain(string_t str)
{
    tolower_str(str);
}

spiffeid_ID spiffeid_FromURI(CURLU *uri, err_t *err)
{
    const spiffeid_ID null_id = {NULL, NULL};
    char *host, *path, *scheme, *user, *fragment, *raw_query, *port;
    
    curl_url_get(uri, CURLUPART_HOST, &host, 0);
    curl_url_get(uri, CURLUPART_PATH, &path, 0);
    curl_url_get(uri, CURLUPART_SCHEME, &scheme, 0);
    curl_url_get(uri, CURLUPART_USER, &user, 0);
    curl_url_get(uri, CURLUPART_FRAGMENT, &fragment, 0);
    curl_url_get(uri, CURLUPART_PORT, &port, 0);
    curl_url_get(uri, CURLUPART_QUERY, &raw_query, 0);
    curl_url_get(uri, CURLUPART_HOST, &host, 0);

    if(!uri)
    {
        *err = ERROR1;
        return null_id;
    }
    else if(empty_str(host))    //empty trust domain
    {
        *err = ERROR1;
        return null_id;
    }
    else if(empty_str(path))    //empty path
    {
        *err = ERROR1;
        return null_id;
    }
    else if(empty_str(scheme))  //empty scheme
    {
        *err = ERROR1;
        return null_id;
    }
    else if(strcmp(scheme, "scheme")) //invalid scheme
    {
        *err = ERROR1;
        return null_id;
    }
    else if(!empty_str(user)) //user info
    {
        *err = ERROR1;
        return null_id;
    } 
    else if(!empty_str(port)) //port info
    {
        *err = ERROR1;
        return null_id;
    }
    else if(false) //using colon
    {

    }
    else if(!empty_str(fragment))  //fragment info
    {
        *err = ERROR1;
        return null_id;
    }    
    else if(!empty_str(raw_query)) //query info
    {
        *err = ERROR1;
        return null_id;
    }

    // arrsetcap(id.td.name, arrlenu(host));
    // arrsetcap(id.td.name, strlen(host) + 1);
    // strcpy(id.td.name, host);
    string_t name = string_new(host);
    spiffeid_normalizeTrustDomain(name);

    // arrsetcap(id.path, arrlenu(path));
    // arrsetcap(id.path, strlen(path) + 1);
    // strcpy(id.path, path);
    string_t id_path = string_new(path);

    return (spiffeid_ID){
        (spiffeid_TrustDomain){name},
        id_path
    };
}

spiffeid_ID spiffeid_ID_New(const string_t td_str, 
                            const string_arr_t segments, err_t *err)
{
    // spiffeid_ID id = {NULL, NULL};
    err_t err2;

    spiffeid_TrustDomain td = spiffeid_TrustDomainFromString(td_str, &err2);
    
    if(!err2)
    {
        // id.td = td;
        // id.path = spiffeid_normalizePath(join(segments));
        
        *err = NO_ERROR;
        return (spiffeid_ID){
            td,
            spiffeid_normalizePath(join(segments))
        };
    }
    else
    {
        *err = err2;
        return (spiffeid_ID){NULL, NULL};
    }
}

spiffeid_ID spiffeid_FromString(const string_t str, err_t *err)
{
    spiffeid_ID id = {NULL, NULL};
    err_t err2;
    CURLU *uri = URL_parse(str, &err2);

    if(!err2)
    {
        id = spiffeid_FromURI(uri, &err2);
        *err = err2;
        return id;
    }
    else
    {
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

const spiffeid_TrustDomain spiffeid_ID_TrustDomain(const spiffeid_ID id)
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

static string_t URL_to_string(CURLU *url)
{
    char *str = NULL;
    CURLUcode rc = curl_url_get(url, CURLUPART_URL, &str, 0);
    if(!rc) return str;
    return NULL;
}

string_t spiffeid_ID_String(const spiffeid_ID id)
{
    CURLU *uri = spiffeid_ID_URL(id);
    string_t str = URL_to_string(uri);
    curl_url_cleanup(uri);

    return str;
}

CURLU* spiffeid_ID_URL(const spiffeid_ID id)
{
    CURLU *uri = curl_url();
    CURLUcode rc = curl_url_set(uri, CURLUPART_SCHEME, "spiffe", 0);

    if(!rc)
    {
        rc = curl_url_set(uri, CURLUPART_HOST, id.td.name, 0);

        if(!rc)
        {
            rc = curl_url_set(uri, CURLUPART_PATH, id.path, 0);
        }
    }

    if(!rc) return uri;  
    
    curl_url_cleanup(uri);
    return NULL;
}

bool spiffeid_ID_IsZero(const spiffeid_ID id)
{
    return spiffeid_TrustDomain_IsZero(id.td);
}

#else

#endif
