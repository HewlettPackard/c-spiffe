@mtls @x509
Feature: Mutual TLS


    @Sprint11 @WlB
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


    @Sprint15 @WlB
    Scenario Outline: MT_002 - Check the behavior when the certificate rotates after mtls has been established
        Given The second agent is turned on inside "workload" container
        When  I fetch external "X509" "SVID"
        Then  I check that the "SVID" is returned correctly
        When  I store the "SVID"
        And   I fetch "X509" "SVID"
        Then  I check that the "SVID" is returned correctly
        When  The "<listen_type>"-tls-listen is activated inside "workload" container
        And   I send "Hello World!" to "workload" container through "<dial_type>"-tls-dial
        Then  I check that "Hello World!" was the answer from tls-listen
        When  I fetch external "X509" "SVID"
        Then  I check that the "SVID" is returned correctly
        And   The "SVID" was updated
        When  I send "Hello World!" to "workload" container through "<dial_type>"-tls-dial
        Then  I check that "Hello World!" was the answer from tls-listen
        And   The second "agent" is turned off inside "workload" container
        And   The "<listen_type>"-tls-listen is disabled inside "workload" container
        Examples:
            | dial_type | listen_type |
            |     go    |      go     |
            |     c     |      go     |
            |     go    |      c      |
            |     c     |      c      |


    @Sprint15 @WlB @entry-removed
    Scenario Outline: MT_003 - Check that it is not possible to establish mtls connection if one of the WLs does not have SVID
        Given The "WlB" entry is removed from "spire-server"
        And   The second agent is turned on inside "workload" container
        When  I fetch external "X509" "SVID"
        Then  I check that the "SVID" is not returned
        When  I fetch "X509" "SVID"
        Then  I check that the "SVID" is returned correctly
        When  The "<listen_type>"-tls-listen is activated inside "workload" container
        And   I send "Hello World!" to "workload" container through "<dial_type>"-tls-dial
        Then  I check that mTLS connection did not succeed
        And   The second "agent" is turned off inside "workload" container
        And   The "<listen_type>"-tls-listen is disabled inside "workload" container
        Examples:
            | dial_type | listen_type |
            |     go    |      c      |
            |     c     |      c      |
