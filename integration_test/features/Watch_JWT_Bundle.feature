@watch @JWT @bundle
Feature: Watch JWT Bundle


    @Sprint9
    Scenario: WJB_001 - Check that when rotating the bundle it remains correct and is updated
        When  I fetch "JWT" "Bundle"
        Then  I check that the "Bundle" is returned correctly
        When  I store the "Bundle"
        And   I fetch "JWT" "Bundle"
        Then  I check that the "Bundle" is returned correctly
        And   The "Bundle" was updated


    @Sprint9
    Scenario: WJB_002 - Check the behavior when taking down the agent with watch bundle running and later turn the agent on
        When  I fetch "JWT" "Bundle"
        Then  I check that the "Bundle" is returned correctly
        When  I store the "Bundle"
        And   The agent is turned off
        And   The agent is turned on
        And   I fetch "JWT" "Bundle"
        Then  I check that the "Bundle" is returned correctly
        And   The "Bundle" was updated


    @Sprint9 
    Scenario: WJB_003 - Check the behavior when executing the watch bundle with the agent turned off
        When  I fetch "JWT" "Bundle"
        Then  I check that the "Bundle" is returned correctly
        When  I store the "Bundle"
        And   The agent is turned off
        And   I fetch "JWT" "Bundle"
        Then  I check that the "Bundle" is not returned
        When  The agent is turned on
        And   I fetch "JWT" "Bundle"
        Then  I check that the "Bundle" is returned correctly
        And   The "Bundle" was updated
