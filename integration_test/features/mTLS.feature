@mtls
Feature: Mutual TLS


    @Sprint11
    Scenario Outline: MT_001 - Check that it is possible to establish mtls connection between two WLs connected to the same server
        Given The second agent is turned on inside "workload" container
        When  I fetch external "X509" "SVID"
        Then  I check that the "SVID" is returned correctly
        When  I fetch "X509" "SVID"
        Then  I check that the "SVID" is returned correctly
        When  The go-tls-listen is activated inside "workload" container
        And   I send "<message>" to "workload" container through "<dial_type>"-tls-dial
        Then  I check that "<message>" was the answer from go-tls-listen
        And   The second agent is turned off inside "workload" container
        And   The go-tls-listen is disabled inside "workload" container
        Examples:
            |    message   | dial_type |
            | Hello World! |     go    |
            |              |     go    |
            |     12345    |     go    |
            # | Hello World! |     c     |
            # |              |     c     |
            # |     12345    |     c     |


    @Sprint12 @wip
    Scenario: MT_002 - Check that it is not possible to establish mtls connection with different key chains in the servers
        Given The second agent is turned on inside "workload" container with different key chain
        When  I fetch external "X509" "SVID"
        Then  I check that the "SVID" is returned correctly
        When  I fetch "X509" "SVID"
        Then  I check that the "SVID" is returned correctly
        When  The go-tls-listen is activated inside "workload" container
        And   I send "Hello World!" to "workload" container through "go"-tls-dial
        # Then  I check that "Hello World!" was the answer from go-tls-listen
        Then   The second agent is turned off inside "workload" container
        And   The go-tls-listen is disabled inside "workload" container
