package org.prg.twofactorauth.webauthn;

import org.keycloak.Config;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.authentication.ConfigurableAuthenticatorFactory;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.credential.OTPCredentialModel;
import org.keycloak.provider.ProviderConfigProperty;

import java.util.Collections;
import java.util.List;

public class WebAuthn2MFAAuthenticatorFactory implements AuthenticatorFactory, ConfigurableAuthenticatorFactory {

    private static final String PROVIDER_ID = "webauthn-2fa-authenticator";

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public Authenticator create(KeycloakSession session) {
        return new WebAuthn2MFAAuthenticator();
    }

    @Override
    public void init(Config.Scope scope) {

    }

    @Override
    public String getDisplayType() {
        return "WebAuthn 2FA Authenticator";
    }

    @Override
    public String getHelpText() {
        return "Authenticates users using Yubico WebAuthn for 2FA.";
    }

    @Override
    public String getReferenceCategory() {
        return OTPCredentialModel.TYPE;
    }

    @Override
    public boolean isConfigurable() {
        return true;
    }


    @Override
    public AuthenticationExecutionModel.Requirement[] getRequirementChoices() {
        return REQUIREMENT_CHOICES;
    }
    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return Collections.emptyList();
    }

    @Override
    public boolean isUserSetupAllowed() {
        return true;
    }

    @Override
    public void postInit(org.keycloak.models.KeycloakSessionFactory factory) {
    }

    @Override
    public void close() {
    }
}
