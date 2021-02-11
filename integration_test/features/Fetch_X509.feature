@svid
Feature: Fetch X509


    @Sprint6 @X509
    Scenario: TC_001 - Check that it is possible to fetch the SVID
        When I fetch SVID
        Then I check that the SVID is returned correctly


    @Sprint6 @X509
    Scenario: TC_002 - Check that it is possible to fetch Bundle
        When I fetch bundle
        Then I check that the Bundle is returned correctly


    @Sprint6 @X509
    Scenario: TC_003 - Check that it is not possible to fetch SVID with the sever down
        When I down the server
        And  I fetch SVID
        Then I check that the SVID is not returned
        # Tear Down
        When I up the server


    @Sprint6 @X509
    Scenario: TC_004 - Check that it is not possible to fetch Bundle with the sever down
        When I down the server
        And  I fetch bundle
        Then I check that the Bundle is not returned
        # Tear Down
        When I up the server