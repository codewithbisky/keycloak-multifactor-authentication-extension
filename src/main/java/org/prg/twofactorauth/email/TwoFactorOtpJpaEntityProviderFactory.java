package org.prg.twofactorauth.email;

import org.keycloak.connections.jpa.entityprovider.JpaEntityProvider;
import org.keycloak.connections.jpa.entityprovider.JpaEntityProviderFactory;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.prg.twofactorauth.webauthn.UserAccountsWebauthJpaEntityProvider;

public class TwoFactorOtpJpaEntityProviderFactory implements JpaEntityProviderFactory {

    protected static final String ID = "two-factor-otp-jpa-provider";

    @Override
    public JpaEntityProvider create(KeycloakSession session) {
        return new TwoFactorOtpJpaEntityProvider();
    }

    @Override
    public void init(org.keycloak.Config.Scope config) {
        // Initialization logic, if needed
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {
        // Post-initialization logic, if needed
    }

    @Override
    public void close() {
        // Cleanup resources, if needed
    }

    @Override
    public String getId() {
        return ID;  // Unique provider ID
    }
}
