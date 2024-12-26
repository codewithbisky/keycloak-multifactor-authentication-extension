package org.prg.twofactorauth.webauthn.domain;


import com.yubico.webauthn.RelyingParty;
import com.yubico.webauthn.data.RelyingPartyIdentity;

public class RelyingPartyConfiguration {


    /**
     * RelyingParty is the key object in the Yubico library you must configure it once with the settings
     * that identify the server, for example the domain name of the server.  Yubico library makes no
     * assumptions about what type of database is used to store user information, so it defines an
     * interface com.yubico.webauthn.CredentialRepository that is implemented in this package.
     * <p>
     * see Yuibco docs https://developers.yubico.com/WebAuthn/
     *
     * @param credentialRepository an implementation to save webauthn details to from the databsae
     * @return
     */

    public static RelyingParty relyingParty() {

        CredentialRepositoryImpl credentialRepositoryImpl = new CredentialRepositoryImpl();
        RelyingPartyIdentity rpIdentity =
                RelyingPartyIdentity.builder()
                        .id("localhost") // Set this to a parent domain that covers all subdomains// where
                        .name("CodeWithBisky")
                        .build();

        return RelyingParty.builder()
                .identity(rpIdentity)
                .credentialRepository(credentialRepositoryImpl)
                .allowOriginPort(true)
                .build();

    }
}
