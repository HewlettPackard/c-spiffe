@fetch @JWT @wip
Feature: Fetch JWT


    @Sprint8 @SVID
    Scenario: FJ_001 - Check that it is possible to fetch the JWT SVID
        When I fetch "JWT" SVID
        Then I check that the SVID is returned correctly


    @Sprint8 @SVID
    Scenario: FJ_002 - Check that it is possible to fetch JWT SVID with the server down
        When The server is turned off
        And  I fetch "JWT" SVID
        Then I check that the SVID is returned correctly
        # Tear Down
        When The server is turned on


    @Sprint8 @SVID
    Scenario: FJ_003 - Check that it is not possible to fetch JWT SVID with the agent down
        When The agent is turned off
        And  I fetch "JWT" SVID
        Then I check that the SVID is not returned
        # Tear Down
        When The agent is turned on
