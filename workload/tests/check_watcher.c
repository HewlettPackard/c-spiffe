#include <check.h>
#include "../src/watcher.h"

//callback that sets an int to a value, and ignores the context.
void set_int_callback(workloadapi_X509Context* context, void* _args){
    void** args = (void**) _args;
    int val = (int) arrpop(args);
    int* var = (int *) arrpop(args);
    *var = val;
} 

//callback that increments an int by a value, and ignores the context.
void inc_int_callback(workloadapi_X509Context* context, void* _args){
    void** args = (void**) _args;
    int val = (int) arrpop(args);
    int* var = (int *) arrpop(args);
    *var = *(var) + val;
}

START_TEST(test_workloadapi_Watcher_callback_is_called_on_update_once)
{
    // variable to check callback
    int toModify = 0;
    void** args = NULL;

    arrpush(args,(void*) &toModify);
    arrpush(args,(void*) 10);
    
    //callback object
    workloadapi_X509Callback callback;
    callback.func = set_int_callback;
    callback.args = (void*) args;

    //add callback to watcher.
    workloadapi_Watcher* watcher = calloc(1,sizeof *watcher);
    watcher->x509Callback = callback;

    //call update -> toModify = 10
    workloadapi_Watcher_OnX509ContextUpdate(watcher,NULL);
    arrfree(args);
    ck_assert_int_eq(toModify, 10);
    
    
    arrpush(args,(void*) &toModify);
    arrpush(args,(void*) 2);
    callback.func = inc_int_callback;
    callback.args = (void*) args;
    watcher->x509Callback = callback;

    //call update -> toModify += 2
    workloadapi_Watcher_OnX509ContextUpdate(watcher,NULL);
    ck_assert_int_eq(toModify, 12);
    arrfree(args);

    arrpush(args,(void*) &toModify);
    arrpush(args,(void*) 5);
    callback.func = inc_int_callback;
    callback.args = (void*) args;
    watcher->x509Callback = callback;
    
    //call update -> toModify += 5
    workloadapi_Watcher_OnX509ContextUpdate(watcher,NULL);
    ck_assert_int_eq(toModify, 17);
    arrfree(args);
    free(watcher);
}
END_TEST

void empty_callback(workloadapi_X509Context* context, void* _args){
    return;
}

START_TEST(test_workloadapi_newWatcher_creates_client_if_null)
{
    // empty but valid callback object
    workloadapi_X509Callback callback;
    callback.func = empty_callback;
    callback.args = NULL;

    // empty but valid watcher config
    workloadapi_WatcherConfig config;
    config.client = NULL; //client == NULL means create a new one.
    config.clientOptions = NULL;
    
    // error not set.
    err_t error = NO_ERROR;

    //create watcher with null client.    
    workloadapi_Watcher* watcher = workloadapi_newWatcher(config,callback,&error);
    
    // new watcher succeded
    ck_assert_ptr_ne(watcher,NULL);
    // a new client was created and watcher owns it.
    ck_assert_ptr_ne(watcher->client,NULL);
    ck_assert_int_eq(watcher->ownsClient,true);

    // There was no error.
    ck_assert_uint_eq(error,NO_ERROR);

    ///TODO: check if client is valid by...?

    //free allocated watcher.
    workloadapi_freeWatcher(watcher);
}
END_TEST

START_TEST(test_workloadapi_newWatcher_uses_provided_client)
{
    // empty but valid callback object
    workloadapi_X509Callback callback;
    callback.func = empty_callback;
    callback.args = NULL;

    // empty but valid watcher config
    workloadapi_WatcherConfig config;
    config.client = (void*) 1; //non-null already exists;
    config.clientOptions = NULL;
    
    // error not set.
    err_t error = NO_ERROR;

    //create watcher with null client.    
    workloadapi_Watcher* watcher = workloadapi_newWatcher(config,callback,&error);
    
    // new watcher succeded
    ck_assert_ptr_ne(watcher,NULL);

    // uses client provided, and doesn't own client.
    ck_assert_ptr_eq(watcher->client,(void*) 1);
    ck_assert_int_eq(watcher->ownsClient,false);

    // There was no error.
    ck_assert_uint_eq(error,NO_ERROR);

    ///TODO: check if client is valid by...?

    //free allocated watcher.
    error = workloadapi_freeWatcher(watcher);
    ck_assert_int_eq(error,NO_ERROR);
}
END_TEST


Suite* client_suite(void)
{
    Suite *s = suite_create("watcher");
    TCase *tc_core = tcase_create("core");

    tcase_add_test(tc_core, test_workloadapi_Watcher_callback_is_called_on_update_once);
    tcase_add_test(tc_core, test_workloadapi_newWatcher_creates_client_if_null);
    tcase_add_test(tc_core, test_workloadapi_newWatcher_uses_provided_client);

    suite_add_tcase(s, tc_core);

    return s;
}

int main(int argc, char **argv)
{
    Suite *s = client_suite();
    SRunner *sr = srunner_create(s);
    // testing::InitGoogleMock(&argc, argv);
    srunner_run_all(sr, CK_NORMAL);
    const int number_failed = srunner_ntests_failed(sr);
    
    srunner_free(sr);
    
    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
