@federation @x509 @bundle @WlC
Feature: Federation X509 Bundle

    
    Background: Set configuration file for a second spire-server and agent
        Given I set the "server" "port" to "9090" inside "spire-server2" container
        And   I set the "server" "trust domain" to "example2.org" inside "spire-server2" container
        And   I set the "agent" "port" to "9090" inside "workload2" container
        And   I set the "agent" "trust domain" to "example2.org" inside "workload2" container
        And   I set the "agent" "server address" to "spire-server2" inside "workload2" container


    @Sprint15 @updated-conf @WlC
    Scenario Outline: FXB_001 - Check that it is possible to establish mtls connection between two WLs connected to different servers in a Federation
        Given I set federation config to "example.org" inside "spire-server2"
        And   I set federation config to "example2.org" inside "spire-server"
        And   The server is turned on
        And   The second server is turned on inside "spire-server2" container
        And   Federation is activated between "spire-server" and "spire-server2"
        And   The agent is turned on
        And   The second agent is turned on inside "workload2" container with the second trust domain        
        When  I fetch external "X509" "SVID"
        Then  I check that the "SVID" is returned correctly
        When  I fetch "X509" "SVID"
        Then  I check that the "SVID" is returned correctly
        When  The "<listen_type>"-tls-listen is activated inside "workload2" container
        And   I send "Hello World!" to "workload2" container through "<dial_type>"-tls-dial
        Then  I check that "Hello World!" was the answer from tls-listen
        And   The "<listen_type>"-tls-listen is disabled inside "workload2" container
        And   The second "agent" is turned off inside "workload2" container
        And   The agent is turned off
        And   I remove federation configuration from "spire-server"
        And   I remove federation configuration from "spire-server2"
        And   The second "server" is turned off inside "spire-server2" container
        And   The server is turned off
        Examples:
            | dial_type | listen_type |
            |     go    |      go     |
            |     c     |      go     |
            |     go    |      c      |
            |     c     |      c      |


    @Sprint12 @updated-conf @WlC
    Scenario Outline: FXB_003 - Check that it is not possible to establish mtls connection between two WLs connected to different servers that are not in a Federation
        Given The server is turned on
        And   The agent is turned on
        And   The second server is turned on inside "spire-server2" container
        And   The second agent is turned on inside "workload2" container with the second trust domain
        When  I fetch external "X509" "SVID"
        Then  I check that the "SVID" is returned correctly
        When  I fetch "X509" "SVID"
        Then  I check that the "SVID" is returned correctly
        When  The "<listen_type>"-tls-listen is activated inside "workload2" container
        And   I send "Hello World!" to "workload2" container through "<dial_type>"-tls-dial
        Then  I check that mTLS connection did not succeed
        And   The second "agent" is turned off inside "workload2" container
        And   The second "server" is turned off inside "spire-server2" container
        And   The "<listen_type>"-tls-listen is disabled inside "workload2" container
        And   The agent is turned off
        And   The server is turned off
        Examples:
            | dial_type | listen_type |
            |     go    |      go     |
            |     c     |      go     |
            |     go    |      c      |
            |     c     |      c      |
