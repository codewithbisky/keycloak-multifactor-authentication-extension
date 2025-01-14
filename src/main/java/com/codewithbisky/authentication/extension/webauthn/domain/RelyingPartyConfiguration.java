package com.codewithbisky.authentication.extension.webauthn.domain;


import com.codewithbisky.authentication.extension.webauthn.model.UserAccount;
import com.yubico.webauthn.RelyingParty;
import com.yubico.webauthn.data.RelyingPartyIdentity;
import org.jboss.logging.Logger;
import com.codewithbisky.authentication.extension.exception.MissingConfigException;

import java.util.Optional;

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
    private static final Logger logger = Logger.getLogger(RelyingPartyConfiguration.class);

    public static RelyingParty relyingParty(UserService userService, UserAccount userAccount) {


        String domain = System.getenv("KC_WEBAUTHN_DOMAIN");
        String webauthnName = System.getenv("KC_WEBAUTHN_NAME");
        if (domain == null) {
            throw new MissingConfigException("KC_WEBAUTHN_DOMAIN environment variable not set");
        }
        CredentialRepositoryImpl credentialRepositoryImpl = new CredentialRepositoryImpl(userService,
                userAccount == null ? Optional.empty() : Optional.of(userAccount));
        RelyingPartyIdentity rpIdentity =
                RelyingPartyIdentity.builder()
                        .id(domain) // Set this to a parent domain that covers all subdomains// where
                        .name(webauthnName == null ? "CodeWithBisky" : webauthnName)
                        .build();

        return RelyingParty.builder()
                .identity(rpIdentity)
                .credentialRepository(credentialRepositoryImpl)
                .allowOriginPort(true)
                .build();
    }
}
