#include "c-spiffe/workload/jwtcallback.h"
#include "c-spiffe/workload/jwtwatcher.h"
#include <check.h>

// callback that sets an int to a value, and ignores the context.
void set_int_callback(jwtbundle_Set *bundle_set, void *_args)
{
    void **args = (void **) _args;
    long int val = (long int) arrpop(args);
    long int *var = (long int *) arrpop(args);
    *var = val;
}

// callback that increments an int by a value, and ignores the context.
void inc_int_callback(jwtbundle_Set *bundle_set, void *_args)
{
    void **args = (void **) _args;
    long int val = (long int) arrpop(args);
    long int *var = (long int *) arrpop(args);
    *var = *(var) + val;
}

START_TEST(test_workloadapi_JWTWatcher_callback_is_called_on_update_once)
{
    // variable to check callback
    long int toModify = 0;
    void **args = NULL;

    arrpush(args, (void *) &toModify);
    arrpush(args, (void *) 10);

    // callback object
    workloadapi_JWTCallback callback;
    callback.func = set_int_callback;
    callback.args = (void *) args;

    // add callback to watcher.
    workloadapi_JWTWatcher *watcher
        = (workloadapi_JWTWatcher *) calloc(1, sizeof *watcher);
    watcher->jwt_callback = callback;

    // call update -> toModify = 10
    workloadapi_JWTWatcher_OnJWTBundlesUpdate(watcher, NULL);
    arrfree(args);
    ck_assert_int_eq(toModify, 10);

    arrpush(args, (void *) &toModify);
    arrpush(args, (void *) 2);
    callback.func = inc_int_callback;
    callback.args = (void *) args;
    watcher->jwt_callback = callback;

    // call update -> toModify += 2
    workloadapi_JWTWatcher_OnJWTBundlesUpdate(watcher, NULL);
    ck_assert_int_eq(toModify, 12);
    arrfree(args);

    arrpush(args, (void *) &toModify);
    arrpush(args, (void *) 5);
    callback.func = inc_int_callback;
    callback.args = (void *) args;
    watcher->jwt_callback = callback;

    // call update -> toModify += 5
    workloadapi_JWTWatcher_OnJWTBundlesUpdate(watcher, NULL);
    ck_assert_int_eq(toModify, 17);
    arrfree(args);
    free(watcher);
}
END_TEST

void empty_callback(jwtbundle_Set *bundle_set, void *_args) { return; }

START_TEST(test_workloadapi_newJWTWatcher_creates_client_if_null)
{
    // empty but valid callback object
    workloadapi_JWTCallback callback;
    callback.func = empty_callback;
    callback.args = NULL;

    // empty but valid watcher config
    workloadapi_JWTWatcherConfig config;
    config.client = NULL; // client == NULL means create a new one.
    config.client_options = NULL;

    // error not set.
    err_t error = NO_ERROR;

    // create watcher with null client.
    workloadapi_JWTWatcher *watcher
        = workloadapi_newJWTWatcher(config, callback, &error);

    // new watcher succeded
    ck_assert_ptr_ne(watcher, NULL);
    // a new client was created and watcher owns it.
    ck_assert_ptr_ne(watcher->client, NULL);
    ck_assert_int_eq(watcher->owns_client, true);

    // There was no error.
    ck_assert_uint_eq(error, NO_ERROR);

    // free allocated watcher.
    workloadapi_JWTWatcher_Free(watcher);
}
END_TEST

START_TEST(test_workloadapi_newJWTWatcher_uses_provided_client)
{
    // empty but valid callback object
    workloadapi_JWTCallback callback;
    callback.func = empty_callback;
    callback.args = NULL;

    // empty but valid watcher config
    workloadapi_JWTWatcherConfig config;
    config.client = (workloadapi_Client *) 1; // non-null already exists;
    config.client_options = NULL;

    // error not set.
    err_t error = NO_ERROR;

    // create watcher with null client.
    workloadapi_JWTWatcher *watcher
        = workloadapi_newJWTWatcher(config, callback, &error);

    // new watcher succeded
    ck_assert_ptr_ne(watcher, NULL);

    // uses client provided, and doesn't own client.
    ck_assert_ptr_eq(watcher->client, (void *) 1);
    ck_assert_int_eq(watcher->owns_client, false);

    // There was no error.
    ck_assert_uint_eq(error, NO_ERROR);

    // free allocated watcher.
    error = workloadapi_JWTWatcher_Free(watcher);
    ck_assert_int_eq(error, NO_ERROR);
}
END_TEST

void setAddress(workloadapi_Client *client, void *not_used)
{
    workloadapi_Client_SetAddress(client, "http://example.com");
}
void setHeader(workloadapi_Client *client, void *not_used)
{
    workloadapi_Client_SetHeader(client, "workload.example.io", "true");
}

START_TEST(test_workloadapi_newJWTWatcher_applies_Options)
{
    // empty but valid callback object
    workloadapi_JWTCallback callback;
    callback.func = empty_callback;
    callback.args = NULL;

    // empty but valid watcher config
    workloadapi_JWTWatcherConfig config;
    config.client_options = NULL;

    // error not set.
    err_t error = NO_ERROR;

    config.client = workloadapi_NewClient(&error);
    arrput(config.client_options, setAddress);
    arrput(config.client_options, setHeader);

    // create watcher with null client.
    workloadapi_JWTWatcher *watcher
        = workloadapi_newJWTWatcher(config, callback, &error);

    // new watcher succeded
    ck_assert_ptr_ne(watcher, NULL);
    // a new client was created and watcher owns it.
    ck_assert_ptr_eq(watcher->client, config.client);
    ck_assert_int_eq(watcher->owns_client, false);

    ck_assert_ptr_ne(config.client->address, NULL);
    ck_assert_uint_eq(strlen(config.client->address),
                      strlen("http://example.com"));
    ck_assert_uint_eq(strcmp(config.client->address, "http://example.com"), 0);

    ck_assert_ptr_ne(config.client->headers, NULL);
    ck_assert_uint_eq(strlen(config.client->headers[0]),
                      strlen("workload.example.io"));
    ck_assert_uint_eq(strlen(config.client->headers[1]), strlen("true"));
    ck_assert_uint_eq(strcmp(config.client->headers[0], "workload.example.io"),
                      0);
    ck_assert_uint_eq(strcmp(config.client->headers[1], "true"), 0);

    // There was no error.
    ck_assert_uint_eq(error, NO_ERROR);

    // free allocated watcher.
    workloadapi_Client_Free(config.client);
    workloadapi_JWTWatcher_Free(watcher);
}
END_TEST

int waitAndUpdate(void *args)
{
    struct timespec now = { 3, 0 };
    thrd_sleep(&now, NULL);
    workloadapi_JWTWatcher_TriggerUpdated((workloadapi_JWTWatcher *) args);
    return 0;
}

START_TEST(test_workloadapi_JWTWatcher_TimedWaitUntilUpdated_blocks);
{
    // empty but valid callback object
    workloadapi_JWTCallback callback;
    callback.func = empty_callback;
    callback.args = NULL;

    // empty but valid watcher config
    workloadapi_JWTWatcherConfig config;
    config.client_options = NULL;

    // error not set.
    err_t error = NO_ERROR;

    config.client = workloadapi_NewClient(&error);
    arrput(config.client_options, setAddress);
    arrput(config.client_options, setHeader);

    workloadapi_JWTWatcher *watcher
        = workloadapi_newJWTWatcher(config, callback, &error);

    struct timespec then;
    timespec_get(&then, TIME_UTC);
    thrd_t thread;
    thrd_create(&thread, waitAndUpdate, watcher);
    struct timespec timeout = then;
    timeout.tv_sec += 5;
    workloadapi_JWTWatcher_TimedWaitUntilUpdated(watcher, &timeout);

    struct timespec now;
    timespec_get(&now, TIME_UTC);

    ck_assert_int_ge(now.tv_sec, then.tv_sec + 2);
    ck_assert_int_lt(now.tv_sec, then.tv_sec + 5);

    // free allocated watcher.
    workloadapi_Client_Free(config.client);
    workloadapi_JWTWatcher_Free(watcher);
}
END_TEST

START_TEST(test_workloadapi_JWTWatcher_WaitUntilUpdated_blocks);
{
    // empty but valid callback object
    workloadapi_JWTCallback callback;
    callback.func = empty_callback;
    callback.args = NULL;

    // empty but valid watcher config
    workloadapi_JWTWatcherConfig config;
    config.client_options = NULL;

    // error not set.
    err_t error = NO_ERROR;

    config.client = workloadapi_NewClient(&error);
    arrput(config.client_options, setAddress);
    arrput(config.client_options, setHeader);

    workloadapi_JWTWatcher *watcher
        = workloadapi_newJWTWatcher(config, callback, &error);

    struct timespec then;
    timespec_get(&then, TIME_UTC);
    thrd_t thread;
    thrd_create(&thread, waitAndUpdate, watcher);

    workloadapi_JWTWatcher_WaitUntilUpdated(watcher);

    struct timespec now;
    timespec_get(&now, TIME_UTC);

    ck_assert_int_ge(now.tv_sec, then.tv_sec + 2);
    ck_assert_int_lt(now.tv_sec, then.tv_sec + 5);

    // free allocated watcher.
    workloadapi_Client_Free(config.client);
    workloadapi_JWTWatcher_Free(watcher);
}
END_TEST

START_TEST(test_workloadapi_JWTWatcher_Start_blocks);
{
    // empty but valid callback object
    workloadapi_JWTCallback callback;
    callback.func = empty_callback;
    callback.args = NULL;

    // empty but valid watcher config
    workloadapi_JWTWatcherConfig config;
    config.client_options = NULL;

    // error not set.
    err_t error = NO_ERROR;

    config.client = NULL; // no client = create client
    arrput(config.client_options, setAddress);
    arrput(config.client_options, setHeader);

    workloadapi_JWTWatcher *watcher
        = workloadapi_newJWTWatcher(config, callback, &error);

    struct timespec then;
    timespec_get(&then, TIME_UTC);
    thrd_t thread;
    thrd_create(&thread, waitAndUpdate, watcher);
    error = workloadapi_JWTWatcher_Start(watcher);

    ck_assert(!watcher->closed);
    struct timespec now;
    timespec_get(&now, TIME_UTC);

    ck_assert_int_ge(now.tv_sec, then.tv_sec + 2);
    ck_assert_int_lt(now.tv_sec, then.tv_sec + 5);

    // close watcher
    error = workloadapi_JWTWatcher_Close(watcher);

    // free allocated watcher.
    workloadapi_JWTWatcher_Free(watcher);
}
END_TEST

START_TEST(test_workloadapi_JWTWatcher_Close);
{
    // empty but valid callback object
    workloadapi_JWTCallback callback;
    callback.func = empty_callback;
    callback.args = NULL;

    // empty but valid watcher config
    workloadapi_JWTWatcherConfig config;
    config.client_options = NULL;
    config.client = NULL; // no client = create client

    arrput(config.client_options, setAddress);
    // arrput(config.client_options,setHeader);
    // error not set.
    err_t error = NO_ERROR;

    workloadapi_JWTWatcher *watcher
        = workloadapi_newJWTWatcher(config, callback, &error);

    ck_assert(watcher->closed);
    ck_assert_ptr_ne(watcher->client, NULL);
    ck_assert(watcher->client->closed);
    ck_assert(!watcher->client->owns_stub);
    ck_assert_ptr_eq(watcher->client->stub, NULL);

    struct timespec then;
    timespec_get(&then, TIME_UTC);
    thrd_t thread;
    thrd_create(&thread, waitAndUpdate, watcher); // unblocks thread

    error = workloadapi_JWTWatcher_Start(watcher);
    ck_assert(!watcher->closed);

    struct timespec now;
    timespec_get(&now, TIME_UTC);

    ck_assert_int_ge(now.tv_sec, then.tv_sec + 2);
    ck_assert_int_lt(now.tv_sec, then.tv_sec + 5);

    error = workloadapi_JWTWatcher_Close(watcher);

    ck_assert(watcher->closed);
    ck_assert(watcher->close_error == NO_ERROR);
    ck_assert_ptr_ne(watcher->client, NULL);
    // free allocated watcher.
    workloadapi_JWTWatcher_Free(watcher);
}
END_TEST

Suite *watcher_suite(void)
{
    Suite *s = suite_create("jwt_watcher");
    TCase *tc_core = tcase_create("core");
    tcase_add_test(
        tc_core,
        test_workloadapi_JWTWatcher_callback_is_called_on_update_once);
    tcase_add_test(tc_core,
                   test_workloadapi_newJWTWatcher_creates_client_if_null);
    tcase_add_test(tc_core,
                   test_workloadapi_newJWTWatcher_uses_provided_client);
    tcase_add_test(tc_core, test_workloadapi_newJWTWatcher_applies_Options);
    tcase_add_test(tc_core,
                   test_workloadapi_JWTWatcher_TimedWaitUntilUpdated_blocks);
    tcase_add_test(tc_core,
                   test_workloadapi_JWTWatcher_WaitUntilUpdated_blocks);
    tcase_add_test(tc_core, test_workloadapi_JWTWatcher_Start_blocks);
    tcase_add_test(tc_core, test_workloadapi_JWTWatcher_Close);

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
