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
