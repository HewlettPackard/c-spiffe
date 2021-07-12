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
