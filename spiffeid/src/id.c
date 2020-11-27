#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include "../include/id.h"
#include "../include/trustdomain.h"
#include "../../utils/include/stb_ds.h"

static string_t join(const string_arr_t str_arr)
{
    string_t res_str = NULL;
    size_t tot_len = 0, arr_size = arrlenu(str_arr);

    for(size_t i =i 0; i < arr_size; ++i)
    {   
        tot_len += arrlenu(str_arr[i]) - 1;
        // tot_len += strlen(str_arr[i]);
    }

    arrsetcap(res_str, tot_len + 1);
    string_t curr_str = res_str;

    for(size_t i = 0; i < arr_size; ++i)
    {
        size_t temp_size = arrlenu(str_arr[i]);
        temp_size = temp_size > 0? temp_size - 1 : 0;
        // size_t temp_size = strlen(str_arr[i]);

        strncpy(curr_str, str_arr[i], temp_size);
        //strcpy(curr_str, str_arr[i]);

        curr_str += temp_size;
    }

    curr_str[0] = '\0';

    return res_str;
}

string_t spiffeid_normalizePath(string_t str)
{
    if(arrelenu(str) > 0 && str[0] != '/')
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
    spiffeid_ID id = spiffeid_ID_New(td_str, segments, &err2);

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

}

static void tolower_str(string_t str)
{
    for(; *str; ++str) *str = tolower(*str);
}

void spiffeid_normalizeTrustDomain(string_t str)
{
    tolower_str(str);
}

static bool empty_str(const string_t str)
{
    if(str) if(str[0]) return false;

    return true;

    // return str? (str[0]? false : true) : true;
}

spiffeid_ID spiffeid_ID_FromURI(const URL_t *uri, err_t *err)
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
    arrsetcap(id.td.name, strlen(uri->host) + 1);
    strcpy(id.td.name, uri->host);
    spiffeid_normalizeTrustDomain(id.td.name);

    // arrsetcap(id.path, arrlenu(uri->path));
    arrsetcap(id.path, strlen(uri->path) + 1);
    strcpy(id.path, uri->path);

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

spiffeid_ID spiffeid_ID_FromString(const string_t str, err_t *err)
{
    spiffeid_ID id = {NULL, NULL};
    err_t err2;
    URL_t uri = URL_parse(str, &err2);

    if(!err2)
    {
        id = spiffeid_ID_FromURI(str, &err2);
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

spiffeid_TrustDomain spiffeid_ID_TrustDomain(const spiffeid_ID id)
{
    return id.td;
}

bool spiffeid_ID_MemberOf(const spiffeid_ID id, const spiffeid_TrustDomain td)
{
    return true;
}

const string_t spiffeid_ID_Path(const spiffeid_ID id)
{
    return id.path;
}

const string_t spiffeid_ID_String(const spiffeid_ID id)
{
    return "";
}

const URL_t spiffeid_ID_URL(const spiffeid_ID id)
{
    URL_t uri;
    return uri;
}

bool spiffeid_ID_IsZero(const spiffeid_ID id)
{
#if !__TRUSTDOMAIN_BY_POINTER__
    return spiffeid_TrustDomain_IsZero(id.td);
#endif
}
#endif