package org.prg.twofactorauth.webauthn.domain;

import jakarta.persistence.EntityManager;
import org.keycloak.connections.jpa.JpaConnectionProvider;
import org.keycloak.models.KeycloakSession;

import java.sql.SQLException;

public class DbUtil {

    public static EntityManager getEntityManager(KeycloakSession session) throws SQLException {

       return session.getProvider(JpaConnectionProvider.class).getEntityManager();
    }
}