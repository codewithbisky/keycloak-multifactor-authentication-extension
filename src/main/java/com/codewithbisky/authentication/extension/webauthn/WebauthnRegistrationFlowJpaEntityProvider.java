package com.codewithbisky.authentication.extension.webauthn;

import org.keycloak.connections.jpa.entityprovider.JpaEntityProvider;
import com.codewithbisky.authentication.extension.webauthn.entity.RegistrationFlowEntity;

import java.util.List;

public class WebauthnRegistrationFlowJpaEntityProvider implements JpaEntityProvider {

    // List of your JPA entities (custom entities).
    @Override
    public List<Class<?>> getEntities() {
        // Return a list of your custom entities.
        return List.of(RegistrationFlowEntity.class);
    }

    // This is used to return the location of the Liquibase changelog file.
    // You can return null if you don't want Liquibase to create and update the DB schema.
    @Override
    public String getChangelogLocation() {
        // Return the path to your Liquibase changelog file.
        return "META-INF/changelog-webauthn_registration_flow.xml";
    }

    // Helper method, which will be used internally by Liquibase.
    @Override
    public String getFactoryId() {
        return WebauthnRegistrationFlowJpaEntityProviderFactory.ID;
    }


    // Close the provider. This will be called when Keycloak shuts down.
    @Override
    public void close() {
        // Cleanup logic (optional).
    }


}

