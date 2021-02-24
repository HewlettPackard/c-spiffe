@bundle
Feature: Watch X509 Bundle


    Background: Setup to rotate bundle
        Given I set the server to rotate the Bundle up to "15s"


    @Sprint7 @X509
    Scenario: TC_001 - Check that when rotating the bundle it remains correct and is updated
        When  I fetch Bundle
        Then  I check that the Bundle is returned correctly
        When  I store the Bundle
        And   I fetch Bundle
        Then  The Bundle was updated


    @Sprint7 @X509 @wip
    Scenario: TC_002 - Check the behavior when taking down the server with watch bundle running and later turn the server and agent on
        When  I fetch Bundle
        Then  I check that the Bundle is returned correctly
        When  I store the Bundle
        And   The server is turned off
        And   The server is turned on
        And   I fetch Bundle
        Then  The Bundle was updated
