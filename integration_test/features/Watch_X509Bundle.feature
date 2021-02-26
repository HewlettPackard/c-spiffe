@watch @bundle @X509
Feature: Watch X509 Bundle


    Background: Setup to rotate bundle
        Given I set the server to rotate the Bundle up to "15s"


    @Sprint7 @X509
    Scenario: WXB_001 - Check that when rotating the bundle it remains correct and is updated
        When  I fetch Bundle
        Then  I check that the Bundle is returned correctly
        When  I store the Bundle
        And   I fetch Bundle
        Then  The Bundle was updated


    @Sprint7 @X509
    Scenario: WXB_002 - Check the behavior when taking down the server with watch bundle running and later turn the server on
        When  I fetch Bundle
        Then  I check that the Bundle is returned correctly
        When  I store the Bundle
        And   The server is turned off
        And   The server is turned on
        And   I fetch Bundle
        Then  The Bundle was updated


    @Sprint7 @X509
    Scenario: WXB_003 - Check the behavior when taking down the agent with watch bundle running and later turn the agent on
        When  I fetch Bundle
        Then  I check that the Bundle is returned correctly
        When  I store the Bundle
        And   The agent is turned off
        And   The agent is turned on
        And   I fetch Bundle
        Then  The Bundle was updated


    @Sprint7 @X509
    Scenario: WXB_004 - Check the behavior when executing the watch bundle with the agent turned off
        When  I fetch Bundle
        Then  I check that the Bundle is returned correctly
        When  I store the Bundle
        And   The agent is turned off
        And   I fetch Bundle
        Then  I check that the Bundle is not returned
        When  The agent is turned on
        And   I fetch Bundle
        Then  The Bundle was updated