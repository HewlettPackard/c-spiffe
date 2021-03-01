@fetch @X509
Feature: Fetch X509


    @Sprint6 @X509
    Scenario: FX_001 - Check that it is possible to fetch the X509 SVID
        When I fetch SVID
        Then I check that the SVID is returned correctly


    @Sprint6 @X509
    Scenario: FX_002 - Check that it is possible to fetch the X509 Bundle
        When I fetch Bundle
        Then I check that the Bundle is returned correctly


    @Sprint6 @X509
    Scenario: FX_003 - Check that it is not possible to fetch X509 SVID with the agent down
        When The agent is turned off
        And  I fetch SVID
        Then I check that the SVID is not returned
        # Tear Down
        When The agent is turned on


    @Sprint6 @X509
    Scenario: FX_004 - Check that it is not possible to fetch the X509 Bundle with the agent down
        When The agent is turned off
        And  I fetch Bundle
        Then I check that the Bundle is not returned
        # Tear Down
        When The agent is turned on


    @Sprint8 @X509
    Scenario: FX_005 - Check that it is not possible to fetch X509 SVID with the server down
        When The server is turned off
        And  I fetch SVID
        Then I check that the SVID is not returned
        # Tear Down
        When The server is turned on


    @Sprint8 @X509
    Scenario: FX_006 - Check that it is not possible to fetch the X509 Bundle with the server down
        When The server is turned off
        And  I fetch Bundle
        Then I check that the Bundle is not returned
        # Tear Down
        When The server is turned on
