#include "c-spiffe/spiffeid/id.h"
#include "c-spiffe/spiffeid/trustdomain.h"
#include "c-spiffe/utils/stb_ds.h"
#include <ctype.h>
#include <stdlib.h>
#include <string.h>

string_t join(string_arr_t str_arr)
{
    string_t res_str = NULL;
    const size_t arr_size = arrlenu(str_arr);
    size_t tot_len = 0;
    size_t *len_arr = NULL;

    // insert the slashes on the end of the strings
    // and store their respective lengths
    for(size_t i = 0; i < arr_size - 1; ++i) {
        // tot_len += arrlenu(str_arr[i]) - 1;
        if(!empty_str(str_arr[i])) {
            const size_t last_idx = arrlenu(str_arr[i]);
            arrins(str_arr[i], last_idx - 1, '/');
        }

        const size_t len = strlen(str_arr[i]);
        arrput(len_arr, len);
        tot_len += len;
    }
    // last string does not end with a trailing slash
    const size_t len = strlen(arrlast(str_arr));
    arrput(len_arr, len);
    tot_len += len;

    arrsetlen(res_str, tot_len + 1);
    string_t curr_str = res_str;

    for(size_t i = 0; i < arr_size; ++i) {
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
    // null check
    if(str) {
        if(arrlenu(str) > 0) {
            if(str[0] != '/') {
                // inserts '/' at the beginning
                arrins(str, 0, '/');
            }
        }
    }

    return str;
}

string_t spiffeid_Join(const char *td_str, const string_arr_t segments,
                       err_t *err)
{
    spiffeid_ID id = spiffeid_ID_New(td_str, segments, err);

    if(!(*err)) {
        string_t str_id = spiffeid_ID_String(id);
        spiffeid_ID_Free(&id);
        return str_id;
    } else {
        return NULL;
    }
}

static UriUriA URL_parse(const char *str, err_t *err)
{
    UriUriA uri;
    const char *err_pos;
    if(uriParseSingleUriA(&uri, str, &err_pos) == URI_SUCCESS) {
        *err = NO_ERROR;
    } else {
        *err = ERR_PARSING;
    }

    return uri;
}

static string_t tolower_str(string_t str)
{
    string_t curr_str = str;
    for(; *curr_str; ++curr_str) {
        // in-place change
        *curr_str = tolower(*curr_str);
    }
    return str;
}

string_t spiffeid_normalizeTrustDomain(string_t str)
{
    return tolower_str(str);
}

static string_t UriPathSegmentA_string(
    const UriPathSegmentA *head) //, const UriPathSegmentA *tail)
{
    string_t str_path = string_new("");

    if(head) {
        const UriPathSegmentA *it = head;
        for(; it != NULL; it = it->next) {
            // string from range
            string_t str_seg
                = string_new_range(it->text.first, it->text.afterLast);
            // insert slash at the end
            const size_t len = arrlenu(str_seg);
            arrins(str_seg, len - 1, '/');
            // concatenates string
            str_path = string_push(str_path, str_seg);
            arrfree(str_seg);
        }
        // removes trailing slash
        const size_t len = arrlenu(str_path);
        arrdel(str_path, len - 2);
    }

    return str_path;
}

spiffeid_ID spiffeid_FromURI(const UriUriA *uri, err_t *err)
{
    *err = NO_ERROR;
    string_t host = (string_t) string_new_range(uri->hostText.first,
                                                uri->hostText.afterLast);
    string_t path = UriPathSegmentA_string(uri->pathHead);
    string_t scheme = (string_t) string_new_range(uri->scheme.first,
                                                  uri->scheme.afterLast);
    string_t user = (string_t) string_new_range(uri->userInfo.first,
                                                uri->userInfo.afterLast);
    string_t fragment = (string_t) string_new_range(uri->fragment.first,
                                                    uri->fragment.afterLast);
    string_t raw_query
        = (string_t) string_new_range(uri->query.first, uri->query.afterLast);
    string_t port = (string_t) string_new_range(uri->portText.first,
                                                uri->portText.afterLast);

    if(!uri) {
        *err = ERR_EMPTY_DATA;
    } else if(empty_str(host)) // empty trust domain
    {
        *err = ERR_EMPTY_DATA;
    } else if(empty_str(scheme)) // empty scheme
    {
        *err = ERR_INVALID_DATA;
    } else if(strcmp(scheme, "spiffe")) // invalid scheme
    {
        *err = ERR_INVALID_DATA;
    } else if(!empty_str(user)) // user info
    {
        *err = ERR_INVALID_DATA;
    } else if(!empty_str(port)) // port info
    {
        *err = ERR_INVALID_DATA;
    } else if(!empty_str(fragment)) // fragment info
    {
        *err = ERR_NULL_ID;
        // return null_id;
    } else if(!empty_str(raw_query)) // query info
    {
        *err = ERR_NULL_ID;
        // return null_id;
    }

    spiffeid_ID id = { { NULL }, NULL };

    if(!(*err)) {
        string_t name = string_new(host);
        id.td.name = spiffeid_normalizeTrustDomain(name);
        id.path = spiffeid_normalizePath(string_new(path));
    }

    arrfree(host);
    arrfree(path);
    arrfree(scheme);
    arrfree(user);
    arrfree(fragment);
    arrfree(raw_query);
    arrfree(port);

    return id;
}

spiffeid_ID spiffeid_ID_New(const char *td_str, const string_arr_t segments,
                            err_t *err)
{
    spiffeid_TrustDomain td = spiffeid_TrustDomainFromString(td_str, err);
    if(!(*err)) {
        // id.td = td;
        // id.path = spiffeid_normalizePath(join(segments));
        return (spiffeid_ID){ td, spiffeid_normalizePath(join(segments)) };
    } else {
        return (spiffeid_ID){ { NULL }, NULL };
    }
}

spiffeid_ID spiffeid_FromString(const char *str, err_t *err)
{
    spiffeid_ID id = { { NULL }, NULL };
    UriUriA uri = URL_parse(str, err);

    if(!(*err)) {
        id = spiffeid_FromURI(&uri, err);
        uriFreeUriMembersA(&uri);
    }

    return id;
}

void spiffeid_ID_Free(spiffeid_ID *id)
{
    if(id) {
        arrfree(id->td.name);
        arrfree(id->path);
    }
}

spiffeid_TrustDomain spiffeid_ID_TrustDomain(const spiffeid_ID id)
{
    return id.td;
}

bool spiffeid_ID_MemberOf(const spiffeid_ID id, const spiffeid_TrustDomain td)
{
    return !strcmp(id.td.name, td.name);
}

const char *spiffeid_ID_Path(const spiffeid_ID id) { return id.path; }

static string_t URI_to_string(UriUriA *uri)
{
    int len;
    uriToStringCharsRequiredA(uri, &len);

    string_t str_uri = NULL;
    arrsetlen(str_uri, len + 1);

    uriToStringA(str_uri, uri, len + 1, NULL);

    return str_uri;
}

static UriUriA spiffeid_ID_URI(const spiffeid_ID id)
{
    UriUriA uri;
    memset(&uri, 0, sizeof uri);
    string_t scheme = string_new("spiffe");
    string_t host = string_new(id.td.name);
    string_t path = string_new(id.path);

    if(path[0] == '/')
        arrdel(path, 0);

    uri.scheme.first = scheme;
    uri.scheme.afterLast = scheme + arrlenu(scheme) - 1;
    uri.hostText.first = host;
    uri.hostText.afterLast = host + arrlenu(host) - 1;

    uri.pathHead = malloc(sizeof(UriPathSegmentA));
    uri.pathHead->next = NULL;
    uri.pathTail = uri.pathHead;
    uri.pathHead->text.first = path;
    uri.pathHead->text.afterLast = path + arrlenu(path) - 1;

    return uri;
}

string_t spiffeid_ID_String(const spiffeid_ID id)
{
    UriUriA uri = spiffeid_ID_URI(id);
    string_t str = URI_to_string(&uri);
    arrfree(uri.scheme.first);
    arrfree(uri.hostText.first);
    arrfree(uri.pathHead->text.first);
    free(uri.pathHead);

    return str;
}

bool spiffeid_ID_IsZero(const spiffeid_ID id)
{
    return spiffeid_TrustDomain_IsZero(id.td);
}
