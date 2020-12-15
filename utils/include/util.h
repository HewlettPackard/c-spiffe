#ifndef __INCLUDE_UTILS_UTIL_H__
#define __INCLUDE_UTILS_UTIL_H__

#include <stdbool.h>
#include <string.h>
#include <openssl/evp.h>
#include "stb_ds.h"

// typedef bool err_t;
typedef char* string_t;
typedef char** string_arr_t;
typedef unsigned char byte;

typedef struct map_string_EVP_PKEY
{
    string_t key;
    EVP_PKEY *value;
} map_string_EVP_PKEY;

typedef struct map_string_string
{
    string_t key;
    string_t value;
} map_string_string;

enum enum_err_t
{
    NO_ERROR = 0,
    ERROR1,
    ERROR2,
    ERROR3
};

typedef enum enum_err_t err_t;

// void util_string_t_Free(string_t *strptr);
void util_string_t_Free(string_t str, bool alloc);

//allocates, concatenates and returns the new dst pointer
string_t string_push(string_t dst, const string_t src)
{
    const size_t str_size = strlen(src) + 1;
    arraddnptr(dst, str_size);
    strcat(dst, src);

    return dst;
}

string_t string_new(string_t str_src)
{
    const size_t str_size = strlen(str_src) + 1;
    string_t str_new = NULL;
    arrsetcap(str_new, str_size);
    memcpy(str_new, str_src, str_size);

    return str_new;
}

bool empty_str(const string_t str)
{
    if(str) if(str[0]) return false;

    return true;
    // return str? (str[0]? false : true) : true;
}

bool string_contains(const string_t src, const string_t str);

string_t FILE_to_string(FILE *f)
{
    //go to the end of the file
    fseek(f, 0, SEEK_END);
    //get length in bytes
    long int flen = ftell(f);
    //return to the beginning
    rewind(f);
    string_t buffer = NULL;
    //set byte array capacity
    arrsetcap(buffer, flen);
    //read bytes into buffer
    fread(buffer, flen, 1, f);
    
    return buffer;
}

byte* FILE_to_bytes(FILE *f)
{
    return (byte*) FILE_to_string(f);
}

#endif