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

@fetch @X509
Feature: Fetch X509


    @Sprint6 @SVID
    Scenario: FX_001 - Check that it is possible to fetch the X509 SVID
        When I fetch "X509" "SVID"
        Then I check that the "SVID" is returned correctly


    @Sprint6 @Bundle
    Scenario: FX_002 - Check that it is possible to fetch the X509 Bundle
        When I fetch "X509" "Bundle"
        Then I check that the "Bundle" is returned correctly


    @Sprint6 @SVID
    Scenario: FX_003 - Check that it is not possible to fetch X509 SVID with the agent down
        Given The agent is turned off
        When  I fetch "X509" "SVID"
        Then  I check that the "SVID" is not returned
        And   The agent is turned on


    @Sprint6 @Bundle
    Scenario: FX_004 - Check that it is not possible to fetch the X509 Bundle with the agent down
        Given The agent is turned off
        When  I fetch "X509" "Bundle"
        Then  I check that the "Bundle" is not returned
        And   The agent is turned on
