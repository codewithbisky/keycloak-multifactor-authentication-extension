package org.prg.twofactorauth.util;

import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.UserModel;
import org.prg.twofactorauth.MultiFactorAuthenticator;
import org.prg.twofactorauth.MultiFactorAuthenticatorFactory;
import org.prg.twofactorauth.webauthn.credential.WebAuthnCredentialModel;

import java.util.ArrayList;
import java.util.List;

import static org.prg.twofactorauth.util.ProvidersUtil.getWebauthnCredentialProvider;
import static org.prg.twofactorauth.util.ProvidersUtil.getMultiFactorAuthenticatorProvider;

public final class KeycloakSessionUtil {

    private KeycloakSessionUtil() {

    }


    public static List<String> getUserSupportedMfa(UserModel user, KeycloakSession session) {
        List<String> credentials = new ArrayList<>();
        boolean webAuthnConfigured = webAuthnConfigured(user, session);
        if (webAuthnConfigured) {
            credentials.add("webauthn");
        }
        boolean otp = user.credentialManager().getStoredCredentialsByTypeStream("otp").findAny().isPresent();
        if (otp) {
            credentials.add("otp");
        }
        MultiFactorAuthenticator authenticatorProvider = getMultiFactorAuthenticatorProvider(session);

        AuthenticatorConfigModel authenticatorConfig = authenticatorProvider
                .getAuthenticatorConfigByKey(session, MultiFactorAuthenticatorFactory.ENABLE_EMAIL_2ND_AUTHENTICATION);
        if (authenticatorConfig != null && authenticatorConfig.getConfig() != null) {
            String emailConfig = authenticatorConfig.getConfig()
                    .get(MultiFactorAuthenticatorFactory.ENABLE_EMAIL_2ND_AUTHENTICATION);
            if (Boolean.parseBoolean(emailConfig)) {
                credentials.add("email");
            }
        }
        return credentials;
    }

    public static boolean webAuthnConfigured(UserModel user, KeycloakSession session) {
        return getWebauthnCredentialProvider(session).isConfiguredFor(session.getContext().getRealm(), user, WebAuthnCredentialModel.TYPE);
    }
}
