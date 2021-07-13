#ifndef INCLUDE_UTILS_UTIL_H
#define INCLUDE_UTILS_UTIL_H

#include "c-spiffe/utils/stb_ds.h"
#include "c-spiffe/utils/error.h"
#include <openssl/evp.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/** string_t is an stb allocated string. Treat it as a regular string, but
 * deallocate id with util_string_t_Free or arrfree functions. */
typedef char *string_t;
/** string_arr_t is an array of stb allocated strings. Deallocate it with
 * util_string_arr_t_Free or manually iterating using arrfree. */
typedef char **string_arr_t;
typedef unsigned char byte;

typedef struct map_string_EVP_PKEY {
    string_t key;
    EVP_PKEY *value;
} map_string_EVP_PKEY;

typedef struct map_string_string {
    string_t key;
    string_t value;
} map_string_string;


/**
 * Frees stb string.
 *
 * \param str [in] Deallocates stb string. If <tt>NULL</tt> is passed, it
 * has no effects./
 */
void util_string_t_Free(string_t str);

/**
 * Frees stb array of stb strings.
 *
 * \param str_arr [in] Deallocates array. If <tt>NULL</tt> is passed, it
 * has no effects./
 */
void util_string_arr_t_Free(string_arr_t str_arr);

/**
 * Concatenates an stb string and returns its new address.
 *
 * \param dst [in] stb string to be concatenated.
 * \param src [in] Null terminated string.
 * \returns An stb string with dst and src concatenation. The variable
 * holding the old dst value must be updated by the function return value.
 * Must be freed using wither arrfree or util_string_t_Free functions when
 * no longer needed.
 */
string_t string_push(string_t dst, const char *src);

/**
 * New stb string from a C-string.
 *
 * \param str_src [in] Null terminated string.
 * \returns An stb string as a copy of the string passed as parameter. Must
 * be freed using either arrfree or util_string_t_Free functions.
 */
string_t string_new(const char *str_src);

/**
 * New stb string from a string range.
 *
 * \param begin [in] Begining of the string range.
 * \param end [in] Ending of the string range.
 * \returns An stb string as a copy of the string in range [begin, end). A
 * null character is placed at the end. Must be freed using either arrfree
 * or util_string_t_Free functions.
 */
string_t string_new_range(const char *begin, const char *end);

/**
 * Checks if a string is either NULL or empty.
 *
 * \param str [in] null terminated string.
 * \returns <tt>true</tt> if str is either NULL os str[0] == '\0',
 * <tt>false</tt> otherwise.
 */
bool empty_str(const char *str);

/**
 * Checks if a string contains another.
 *
 * \param src [in] Haystack string.
 * \param str [in] Needle string.
 * \returns Same behaviour as strstr(src, str) != NULL
 */
bool string_contains(const char *src, const char *str);

/**
 * Allocates a file into a stb string.
 *
 * \param f [in] file object pointer.
 * \returns An stb string containing the whole file content. The programmer
 * should not make any assumption about the file cursor after the function
 * call. Must be freed using either arrfree or util_string_t_Free
 * functions.
 */
string_t FILE_to_string(FILE *f);

/**
 * Allocates a file into a stb array of bytes.
 *
 * \param f [in] file object pointer.
 * \returns An stb array of bytes containing the whole file content. The
 * programmer should not make any assumption about the file cursor after
 * the function call. Must be freed either using arrfree or
 * util_string_t_Free functions.
 */
byte *FILE_to_bytes(FILE *f);

#ifdef __cplusplus
}
#endif

#endif
