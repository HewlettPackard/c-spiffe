@fetch @X509
Feature: Fetch X509


    @Sprint6 @SVID
    Scenario: FX_001 - Check that it is possible to fetch the X509 SVID
        When I fetch "X509" SVID
        Then I check that the SVID is returned correctly


    @Sprint6 @Bundle
    Scenario: FX_002 - Check that it is possible to fetch the X509 Bundle
        When I fetch "X509" Bundle
        Then I check that the Bundle is returned correctly


    @Sprint6 @SVID
    Scenario: FX_003 - Check that it is not possible to fetch X509 SVID with the agent down
        When The agent is turned off
        And  I fetch "X509" SVID
        Then I check that the SVID is not returned
        # Tear Down
        When The agent is turned on


    @Sprint6 @Bundle
    Scenario: FX_004 - Check that it is not possible to fetch the X509 Bundle with the agent down
        When The agent is turned off
        And  I fetch "X509" Bundle
        Then I check that the Bundle is not returned
        # Tear Down
        When The agent is turned on


    @Sprint8 @SVID
    Scenario: FX_005 - Check that it is possible to fetch X509 SVID with the server down
        When The server is turned off
        And  I fetch "X509" SVID
        Then I check that the SVID is returned correctly
        # Tear Down
        When The server is turned on


    @Sprint8 @Bundle
    Scenario: FX_006 - Check that it is possible to fetch the X509 Bundle with the server down
        When The server is turned off
        And  I fetch "X509" Bundle
        Then I check that the Bundle is returned correctly
        # Tear Down
        When The server is turned on
