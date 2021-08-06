#define STB_DS_IMPLEMENTATION
#include "c-spiffe/utils/util.h"

#include <string.h>

void util_string_t_Free(string_t str)
{
    if(str) {
        arrfree(str);
    }
}

void util_string_arr_t_Free(string_arr_t str_arr)
{
    if(str_arr) {
        for(size_t i = 0, size = arrlenu(str_arr); i < size; ++i) {
            arrfree(str_arr[i]);
        }
        arrfree(str_arr);
    }
}

string_t string_push(string_t dst, const char *src)
{
    if(src) {
        const size_t str_size = strlen(src);
        arraddnptr(dst, str_size);
        strcat(dst, src);
    }

    return dst;
}

string_t string_new(const char *str_src)
{
    if(str_src) {
        const size_t str_size = strlen(str_src) + 1;
        string_t str_new = NULL;
        arrsetlen(str_new, str_size);
        strncpy(str_new, str_src, str_size);

        return str_new;
    }

    return NULL;
}

string_t string_new_range(const char *begin, const char *end)
{
    if((begin && end) && (begin < end)) {
        const size_t str_size = end - begin;
        string_t str_new = NULL;
        arrsetlen(str_new, str_size + 1);
        strncpy(str_new, begin, str_size);
        str_new[str_size] = '\0';

        return str_new;
    }

    return NULL;
}

bool empty_str(const char *str)
{
    if(str)
        if(str[0])
            return false;

    return true;
    // return str? (str[0]? false : true) : true;
}

bool string_contains(const char *src, const char *str)
{
    return strstr(src, str) != NULL;
}

string_t FILE_to_string(FILE *f)
{
    if(f) {
        // go to the end of the file
        fseek(f, 0, SEEK_END);
        // get length in bytes
        const long int flen = ftell(f);
        // return to the beginning
        rewind(f);
        string_t buffer = NULL;
        // set byte array capacity
        arrsetlen(buffer, flen + 1);
        // read bytes into buffer
        size_t end = fread(buffer, 1, flen, f);
        buffer[end] = '\0';

        return buffer;
    }

    return NULL;
}

byte *FILE_to_bytes(FILE *f) { return (byte *) FILE_to_string(f); }
