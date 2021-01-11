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
    ERROR3,
    ERROR4
};

typedef enum enum_err_t err_t;

void util_string_t_Free(string_t str);
void util_string_arr_t_Free(string_arr_t str_arr);

//allocates, concatenates and returns the new dst pointer
string_t string_push(string_t dst, const char *src);

string_t string_new(const char *str_src);

string_t string_new_range(const char *begin, const char *end);

bool empty_str(const char* str);

bool string_contains(const char *src, const char *str);

string_t FILE_to_string(FILE *f);

byte* FILE_to_bytes(FILE *f);

#endif