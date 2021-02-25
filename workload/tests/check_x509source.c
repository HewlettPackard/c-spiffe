#include "../src/x509source.h"
#include "../src/watcher.h"
#include "../../svid/x509svid/src/svid.h"
#include <check.h>


START_TEST(test_workloadapi_X509Source_GetX509SVID_default_picker);
{
    err_t err;
    workloadapi_X509SourceConfig config;
    config.picker = x509svid_SVID_GetDefaultX509SVID;
    config.watcher_config.client_options = NULL;
    config.watcher_config.client = NULL;

    workloadapi_X509Source *tested = workloadapi_NewX509Source(&config,&err);
    
    x509svid_SVID _svid1;
    x509svid_SVID _svid2;
    x509svid_SVID *svid1 = &_svid1;
    x509svid_SVID *svid2 = &_svid2;
    spiffeid_ID id1 = spiffeid_FromString("spiffe://example.org/workload1",&err);
    spiffeid_ID id2 = spiffeid_FromString("spiffe://example.org/workload2",&err);
    _svid1.certs = (X509**) 1;
    _svid2.certs = (X509**) 2;
    _svid1.id = id1;
    _svid2.id = id2;
    _svid1.private_key = NULL;
    _svid2.private_key = NULL;
    
    tested->svids = NULL;

    arrpush(tested->svids,svid1);
    arrpush(tested->svids,svid2);
    tested->closed = false;
    x509svid_SVID *svid3 = workloadapi_X509Source_GetX509SVID(tested, &err);

    ck_assert_ptr_eq(svid3,svid1);
    arrpop(tested->svids);
    arrpop(tested->svids);
    workloadapi_X509Source_Free(tested);
    
}
END_TEST

x509svid_SVID *custom_picker(x509svid_SVID **svids){
    return svids[1];
}

START_TEST(test_workloadapi_X509Source_GetX509SVID_custom_picker);
{
    err_t err;
    workloadapi_X509SourceConfig config;
    config.picker = custom_picker;
    config.watcher_config.client_options = NULL;
    config.watcher_config.client = NULL;
    
    workloadapi_X509Source *tested = workloadapi_NewX509Source(&config,&err);
    
    x509svid_SVID _svid1;
    x509svid_SVID _svid2;
    x509svid_SVID *svid1 = &_svid1;
    x509svid_SVID *svid2 = &_svid2;
    spiffeid_ID id1 = spiffeid_FromString("spiffe://example.org/workload1",&err);
    spiffeid_ID id2 = spiffeid_FromString("spiffe://example.org/workload2",&err);
    _svid1.certs = (X509**) 1;
    _svid2.certs = (X509**) 2;
    _svid1.id = id1;
    _svid2.id = id2;
    _svid1.private_key = NULL;
    _svid2.private_key = NULL;
    
    tested->svids = NULL;

    arrpush(tested->svids,svid1);
    arrpush(tested->svids,svid2);
    tested->closed = false;
    
    x509svid_SVID *svid3 = workloadapi_X509Source_GetX509SVID(tested, &err);

    ck_assert_ptr_eq(svid3,svid2);
    arrpop(tested->svids);
    arrpop(tested->svids);
    workloadapi_X509Source_Free(tested);
    
}
END_TEST



Suite *watcher_suite(void)
{
    Suite *s = suite_create("x509source");
    TCase *tc_core = tcase_create("core");
    
    tcase_add_test(tc_core, test_workloadapi_X509Source_GetX509SVID_default_picker);
    tcase_add_test(tc_core, test_workloadapi_X509Source_GetX509SVID_custom_picker);

    suite_add_tcase(s, tc_core);

    return s;
}

int main(int argc, char **argv)
{
    Suite *s = watcher_suite();
    SRunner *sr = srunner_create(s);
    srunner_run_all(sr, CK_NORMAL);
    const int number_failed = srunner_ntests_failed(sr);

    srunner_free(sr);

    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
