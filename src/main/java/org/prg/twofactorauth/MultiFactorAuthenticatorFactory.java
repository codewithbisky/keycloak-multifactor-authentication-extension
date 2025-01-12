package org.prg.twofactorauth;

import org.keycloak.Config;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.authentication.ConfigurableAuthenticatorFactory;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.credential.OTPCredentialModel;
import org.keycloak.provider.ProviderConfigProperty;
import org.prg.twofactorauth.email.EmailConstants;

import java.util.Collections;
import java.util.List;

public class MultiFactorAuthenticatorFactory implements AuthenticatorFactory, ConfigurableAuthenticatorFactory {

    public static final String PROVIDER_ID = "multi-factor-authenticator";
    public static final String ENABLE_EMAIL_2ND_AUTHENTICATION = "enableEmail2ndAuthentication";

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public Authenticator create(KeycloakSession session) {
        return new MultiFactorAuthenticator();
    }

    @Override
    public void init(Config.Scope scope) {

    }

    @Override
    public String getDisplayType() {
        return "MultiFactor Authenticator Direct Grant";
    }

    @Override
    public String getHelpText() {
        return "Authenticates users using multi factor authentications OTP and WebAuthn (CodeWithBisky.com)";
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
        return List.of(
                new ProviderConfigProperty(EmailConstants.CODE_LENGTH, "Code length",
                        "The number of digits of the generated code.",
                        ProviderConfigProperty.STRING_TYPE, String.valueOf(EmailConstants.DEFAULT_LENGTH)),
                new ProviderConfigProperty(EmailConstants.CODE_TTL, "Time-to-live",
                        "The time to live in seconds for the code to be valid.", ProviderConfigProperty.STRING_TYPE,
                        String.valueOf(EmailConstants.DEFAULT_TTL)),
                new ProviderConfigProperty(ENABLE_EMAIL_2ND_AUTHENTICATION, "Email 2nd Authentication", "Allow email 2nd Authentication for every user", ProviderConfigProperty.BOOLEAN_TYPE, false)
        );
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
