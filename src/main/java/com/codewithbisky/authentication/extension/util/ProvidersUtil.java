package com.codewithbisky.authentication.extension.util;

import com.codewithbisky.authentication.extension.MultiFactorAuthenticator;
import com.codewithbisky.authentication.extension.MultiFactorAuthenticatorFactory;
import com.codewithbisky.authentication.extension.email.EmailAuthenticatorDirectGrant;
import com.codewithbisky.authentication.extension.email.EmailAuthenticatorDirectGrantFactory;
import com.codewithbisky.authentication.extension.webauthn.credential.WebauthnCredentialProvider;
import com.codewithbisky.authentication.extension.webauthn.credential.WebauthnCredentialProviderFactory;
import org.keycloak.authentication.Authenticator;
import org.keycloak.credential.CredentialProvider;
import org.keycloak.models.KeycloakSession;

public final class ProvidersUtil {

    private ProvidersUtil(){

    }



    public static MultiFactorAuthenticator getMultiFactorAuthenticatorProvider(KeycloakSession keycloakSession) {
        return (MultiFactorAuthenticator) keycloakSession.getProvider(Authenticator.class, MultiFactorAuthenticatorFactory.PROVIDER_ID);
    }


    public static WebauthnCredentialProvider getWebauthnCredentialProvider(KeycloakSession keycloakSession) {
        return (WebauthnCredentialProvider) keycloakSession.getProvider(CredentialProvider.class, WebauthnCredentialProviderFactory.PROVIDER_ID);

    }

    public static EmailAuthenticatorDirectGrant getEmailAuthenticatorProvider(KeycloakSession keycloakSession) {
        return (EmailAuthenticatorDirectGrant) keycloakSession.getProvider(Authenticator.class, EmailAuthenticatorDirectGrantFactory.PROVIDER_ID);
    }

    public static CredentialProvider getCredentialProvider(KeycloakSession keycloakSession, String providerId) {
        return keycloakSession.getProvider(CredentialProvider.class, providerId);
    }
}
