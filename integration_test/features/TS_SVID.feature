@svid
Feature: SVI

   # Background: Background for SVID
   # Given I up the spire server
   # And   I up the spire client


    @Sprint6
    Scenario: SC_001 - Check that it is possible to fetch the SVID to request the token
        When I get Spiffe id
        Then I check that Spiffe id is returned


    @Sprint6
    Scenario: SC_002 - Check the token is formed contains the SPIFFE ID
        When I get token
        Then I check that token is returned
