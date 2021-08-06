/**
 *
 * (C) Copyright 2020-2021 Hewlett Packard Enterprise Development LP
 *
 *
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may
 * not use this file except in compliance with the License. You may obtain
 * a copy of the License at
 *
 *
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 *
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 *
 */

#include "c-spiffe/svid/x509svid/source.h"
#include <check.h>

START_TEST(test_x509svid_SourceFromSource)
{
    err_t err;
    x509svid_Source *source
        = x509svid_SourceFromSource(workloadapi_NewX509Source(NULL, &err));

    ck_assert_uint_eq(err, NO_ERROR);
    ck_assert_ptr_ne(source, NULL);

    x509svid_Source_Free(source);
}
END_TEST

Suite *svidsource_suite(void)
{
    Suite *s = suite_create("svid source");
    TCase *tc_core = tcase_create("core");

    tcase_add_test(tc_core, test_x509svid_SourceFromSource);

    suite_add_tcase(s, tc_core);

    return s;
}

int main(void)
{
    Suite *s = svidsource_suite();
    SRunner *sr = srunner_create(s);

    srunner_run_all(sr, CK_NORMAL);
    const int number_failed = srunner_ntests_failed(sr);

    srunner_free(sr);

    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
