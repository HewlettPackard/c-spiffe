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

@fetch @JWT
Feature: Fetch JWT


    @Sprint8 @SVID
    Scenario: FJ_001 - Check that it is possible to fetch the JWT SVID
        When I fetch "JWT" "SVID"
        Then I check that the "SVID" is returned correctly


    @Sprint8 @SVID
    Scenario: FJ_002 - Check that it is not possible to fetch JWT SVID with the agent down
        Given The agent is turned off
        When  I fetch "JWT" "SVID"
        Then  I check that the "SVID" is not returned
        And   The agent is turned on


    @Sprint8 @Bundle
    Scenario: FJ_003 - Check that it is possible to fetch the JWT Bundle
        When I fetch "JWT" "Bundle"
        Then I check that the "Bundle" is returned correctly


    @Sprint8 @Bundle
    Scenario: FJ_004 - Check that it is not possible to fetch JWT Bundle with the agent down
        Given The agent is turned off
        When  I fetch "JWT" "Bundle"
        Then  I check that the "Bundle" is not returned
        And   The agent is turned on
