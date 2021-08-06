# (C) Copyright 2020-2021 Hewlett Packard Enterprise Development LP
#
# 
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
# 
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# 
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

@watch @X509 @bundle
Feature: Watch X509 Bundle


    @Sprint7
    Scenario: WXB_001 - Check that when rotating the bundle it remains correct and is updated
        When  I fetch "X509" "Bundle"
        Then  I check that the "Bundle" is returned correctly
        When  I store the "Bundle"
        And   I fetch "X509" "Bundle"
        Then  I check that the "Bundle" is returned correctly
        And   The "Bundle" was updated


    @Sprint7
    Scenario: WXB_003 - Check the behavior when taking down the agent with watch bundle running and later turn the agent on
        When  I fetch "X509" "Bundle"
        Then  I check that the "Bundle" is returned correctly
        When  I store the "Bundle"
        And   The agent is turned off
        And   The agent is turned on
        And   I fetch "X509" "Bundle"
        Then  I check that the "Bundle" is returned correctly
        And   The "Bundle" was updated


    @Sprint7
    Scenario: WXB_004 - Check the behavior when executing the watch bundle with the agent turned off
        When  I fetch "X509" "Bundle"
        Then  I check that the "Bundle" is returned correctly
        When  I store the "Bundle"
        And   The agent is turned off
        And   I fetch "X509" "Bundle"
        Then  I check that the "Bundle" is not returned
        When  The agent is turned on
        And   I fetch "X509" "Bundle"
        Then  I check that the "Bundle" is returned correctly
        And   The "Bundle" was updated
