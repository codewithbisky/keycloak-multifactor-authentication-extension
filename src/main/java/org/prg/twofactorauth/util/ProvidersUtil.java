package org.prg.twofactorauth.util;

import org.keycloak.authentication.Authenticator;
import org.keycloak.credential.CredentialProvider;
import org.keycloak.models.KeycloakSession;
import org.prg.twofactorauth.MultiFactorAuthenticator;
import org.prg.twofactorauth.MultiFactorAuthenticatorFactory;
import org.prg.twofactorauth.email.EmailAuthenticatorDirectGrant;
import org.prg.twofactorauth.email.EmailAuthenticatorDirectGrantFactory;
import org.prg.twofactorauth.webauthn.credential.WebauthnCredentialProvider;
import org.prg.twofactorauth.webauthn.credential.WebauthnCredentialProviderFactory;

public final class ProvidersUtil {

    private ProvidersUtil(){

    }



    public static MultiFactorAuthenticator getMultiFactorAuthenticatorProvider(KeycloakSession keycloakSession) {
        return (MultiFactorAuthenticator) keycloakSession.getProvider(Authenticator.class, MultiFactorAuthenticatorFactory.PROVIDER_ID);
    }


    public static WebauthnCredentialProvider getCredentialProvider(KeycloakSession keycloakSession) {
        return (WebauthnCredentialProvider) keycloakSession.getProvider(CredentialProvider.class, WebauthnCredentialProviderFactory.PROVIDER_ID);

    }

    public static EmailAuthenticatorDirectGrant getEmailAuthenticatorProvider(KeycloakSession keycloakSession) {
        return (EmailAuthenticatorDirectGrant) keycloakSession.getProvider(Authenticator.class, EmailAuthenticatorDirectGrantFactory.PROVIDER_ID);
    }
}
