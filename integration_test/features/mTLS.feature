@mtls
@wip
Feature: Mutual TLS


    @Sprint11 @wip2
    Scenario: MT_001 - Check that it is possible to establish mtls connection between two WLs connected to the same server
        Given The second agent is turned on inside "workload" container
        When  I fetch "X509" "SVID"
        Then  I check that the "SVID" is returned correctly
        Given The second agent is turned off inside "workload" container


    @Sprint11
    Scenario: MT_002 - Check that it is not possible to establish mtls connection with different key chains in the servers
        When I fetch "X509" "SVID"
        Then I check that the "SVID" is returned correctly