#include <check.h>
#include "../src/id.h"

START_TEST(test_join)
{
    string_arr_t str_arr = NULL;
    arrput(str_arr, string_new("seg1"));
    arrput(str_arr, string_new("segment2"));
    arrput(str_arr, string_new("s3"));

    string_t res = join(str_arr);
    ck_assert_str_eq(res, "seg1/segment2/s3");

    util_string_arr_t_Free(str_arr);
    util_string_t_Free(res);
}
END_TEST

START_TEST(test_spiffeid_ID_New)
{
    string_arr_t str_arr = NULL;
    arrput(str_arr, string_new("path1"));
    arrput(str_arr, string_new("path1/path22"));
    arrput(str_arr, string_new("p333"));

    err_t err;
    string_t str_td = string_new("example.com");
    spiffeid_ID id = spiffeid_ID_New(str_td, str_arr, &err);

    ck_assert_str_eq(id.td.name, "example.com");
    ck_assert_str_eq(id.path, "/path1/path1/path22/p333");
    util_string_arr_t_Free(str_arr);
    spiffeid_ID_Free(&id, false);
}
END_TEST

START_TEST(test_spiffeid_FromURI)
{
    err_t err;
    UriUriA uri;
    memset(&uri, 0, sizeof uri);

    const char host[] = "example.com";
    const char scheme[] = "spiffe";
    const char path[] = "path1/seg3/rest";

    uri.hostText.first = host;
    uri.hostText.afterLast = host + sizeof host - 1;
    uri.scheme.first = scheme;
    uri.scheme.afterLast = scheme + sizeof scheme - 1;
    
    uri.pathHead = malloc(sizeof(UriPathSegmentA));
    memset(uri.pathHead, 0, sizeof *(uri.pathHead));
    uri.pathHead->next = NULL;
    uri.pathTail = uri.pathHead;
    uri.pathHead->text.first = path;
    uri.pathHead->text.afterLast = path + sizeof path - 1;
    
    spiffeid_ID id = spiffeid_FromURI(&uri, &err);
    ck_assert_str_eq(id.td.name, "example.com");
    ck_assert_str_eq(id.path, "path1/seg3/rest");
}
END_TEST

START_TEST(test_spiffeid_FromString)
{
    const string_t strs[] = {
        string_new("spiffe://example.br/path1"), 
        string_new("https://example.us/path2/path3"), 
        string_new("example.gov/path1"),
        string_new("spiffe://www.anything.com.uk/p1/PATH2/p333J")};
    
    err_t err0, err1, err2, err3;
    spiffeid_ID id0 = spiffeid_FromString(strs[0], &err0);
    spiffeid_ID id1 = spiffeid_FromString(strs[1], &err1);
    spiffeid_ID id2 = spiffeid_FromString(strs[2], &err2);
    spiffeid_ID id3 = spiffeid_FromString(strs[3], &err3);

    ck_assert_str_eq(id0.td.name, "example.br");
    ck_assert_str_eq(id0.path, "path1");
    ck_assert_uint_eq(err0, 0);

    ck_assert(id1.td.name == NULL);
    ck_assert(id1.path == NULL);
    ck_assert_uint_ne(err1, 0);

    ck_assert(id2.td.name == NULL);
    ck_assert(id2.path == NULL);
    ck_assert_uint_ne(err2, 0);

    ck_assert_str_eq(id3.td.name, "www.anything.com.uk");
    ck_assert_str_eq(id3.path, "p1/PATH2/p333J");
    ck_assert_uint_eq(err3, 0);
}
END_TEST

/*START_TEST(test_spiffeid_normalizePath)
{

}
END_TEST

START_TEST(test_spiffeid_ID_String)
{

}
END_TEST

START_TEST(test_spiffeid_Join)
{

}
END_TEST
*/
Suite* util_suite(void)
{
    Suite *s = suite_create("id");
    TCase *tc_core = tcase_create("core");

    tcase_add_test(tc_core, test_join);
    tcase_add_test(tc_core, test_spiffeid_ID_New);
    tcase_add_test(tc_core, test_spiffeid_FromURI);
    tcase_add_test(tc_core, test_spiffeid_FromString);

    suite_add_tcase(s, tc_core);

    return s;
}

int main(void)
{
    Suite *s = util_suite();
    SRunner *sr = srunner_create(s);

    srunner_run_all(sr, CK_NORMAL);
    const int number_failed = srunner_ntests_failed(sr);
    
    srunner_free(sr);
    
    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}