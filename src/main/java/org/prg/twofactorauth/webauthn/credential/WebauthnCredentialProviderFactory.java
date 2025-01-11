package org.prg.twofactorauth.webauthn.credential;

import org.keycloak.credential.CredentialProvider;
import org.keycloak.credential.CredentialProviderFactory;
import org.keycloak.models.KeycloakSession;

public class WebauthnCredentialProviderFactory implements CredentialProviderFactory<WebauthnCredentialProvider> {

    public static final String PROVIDER_ID = "webauth-custom";

    @Override
    public CredentialProvider create(KeycloakSession session) {
        return new WebauthnCredentialProvider(session);
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }
}
