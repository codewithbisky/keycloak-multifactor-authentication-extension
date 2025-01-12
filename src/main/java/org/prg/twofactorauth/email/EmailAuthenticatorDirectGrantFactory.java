package org.prg.twofactorauth.email;

import org.keycloak.Config;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.authentication.ConfigurableAuthenticatorFactory;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.credential.OTPCredentialModel;
import org.keycloak.provider.ProviderConfigProperty;
import org.prg.twofactorauth.MultiFactorAuthenticator;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public class EmailAuthenticatorDirectGrantFactory implements AuthenticatorFactory, ConfigurableAuthenticatorFactory {

    public static final String PROVIDER_ID = "email-authenticator-direct-grant";

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public Authenticator create(KeycloakSession session) {
        return new EmailAuthenticatorDirectGrant();
    }

    @Override
    public void init(Config.Scope scope) {

    }

    @Override
    public String getDisplayType() {
        return "Email Authenticator Direct Grant";
    }

    @Override
    public String getHelpText() {
        return "Authenticates user by email code (CodeWithBisky.com)";
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
                        String.valueOf(EmailConstants.DEFAULT_TTL)));
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
