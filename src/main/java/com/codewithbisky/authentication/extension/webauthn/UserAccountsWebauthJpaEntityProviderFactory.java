package com.codewithbisky.authentication.extension.webauthn;

import org.keycloak.connections.jpa.entityprovider.JpaEntityProvider;
import org.keycloak.connections.jpa.entityprovider.JpaEntityProviderFactory;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;

public class UserAccountsWebauthJpaEntityProviderFactory implements JpaEntityProviderFactory {

    protected static final String ID = "custom-webauth-jpa-provider";

    @Override
    public JpaEntityProvider create(KeycloakSession session) {
        return new UserAccountsWebauthJpaEntityProvider();
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
