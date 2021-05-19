@mtls
Feature: Mutual TLS


    @Sprint11
    Scenario Outline: MT_001 - Check that it is possible to establish mtls connection between two WLs connected to the same server
        Given The second agent is turned on inside "workload" container
        When  I fetch external "X509" "SVID"
        Then  I check that the "SVID" is returned correctly
        When  I fetch "X509" "SVID"
        Then  I check that the "SVID" is returned correctly
        When  The "<listen_type>"-tls-listen is activated inside "workload" container
        And   I send "<message>" to "workload" container through "<dial_type>"-tls-dial
        Then  I check that "<message>" was the answer from tls-listen
        And   The second "agent" is turned off inside "workload" container
        And   The "<listen_type>"-tls-listen is disabled inside "workload" container
        Examples:
            |    message   | dial_type | listen_type |
            | Hello World! |     go    |      go     |
            |              |     go    |      go     |
            |     12345    |     go    |      go     |
            | Hello World! |     c     |      go     |
            |              |     c     |      go     |
            |     12345    |     c     |      go     |
            | Hello World! |     go    |      c      |
            |              |     go    |      c      |
            |     12345    |     go    |      c      |
            | Hello World! |     c     |      c      |
            |              |     c     |      c      |
            |     12345    |     c     |      c      |


    @Sprint12 @updated-conf @wip
    Scenario: MT_002 - Check that it is not possible to establish mtls connection with different key chains in the servers
        Given I set the "server" "port" to "9090" inside "spire-server2" container
        And   I set the "server" "trust domain" to "example2.org" inside "spire-server2" container
        And   The second server is turned on inside "spire-server2" container
        And   I set the "agent" "port" to "9090" inside "workload" container
        And   I set the "agent" "trust domain" to "example2.org" inside "workload" container
        And   I set the "agent" "server address" to "spire-server2" inside "workload" container
        And   The second agent is turned on inside "workload" container with the second trust domain
        # When  I fetch external "X509" "SVID"
        # Then  I check that the "SVID" is returned correctly
        When  I fetch "X509" "SVID"
        Then  I check that the "SVID" is returned correctly
        When  The "go"-tls-listen is activated inside "workload" container
        And   I send "Hello World!" to "workload" container through "c"-tls-dial
        Then  I check that mTLS connection did not succeed
        And   The second "agent" is turned off inside "workload" container
        And   The second "server" is turned off inside "spire-server2" container
        And   The "go"-tls-listen is disabled inside "workload" container
