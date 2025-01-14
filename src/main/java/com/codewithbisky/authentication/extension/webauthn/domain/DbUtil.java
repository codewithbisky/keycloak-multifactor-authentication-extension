package com.codewithbisky.authentication.extension.webauthn.domain;

import jakarta.persistence.EntityManager;
import org.jboss.logging.Logger;
import org.keycloak.connections.jpa.JpaConnectionProvider;
import org.keycloak.models.KeycloakSession;
public class DbUtil {

    private static final Logger logger = Logger.getLogger(DbUtil.class);

    public static EntityManager getEntityManager(KeycloakSession session) {
        try {
            return session.getProvider(JpaConnectionProvider.class).getEntityManager();
        } catch (Exception e) {
            logger.error("Failed to obtain EntityManager from KeycloakSession: ", e);
            throw new IllegalStateException("Could not get EntityManager", e);
        }
    }

    public static EntityManager getOrReopenEntityManager(KeycloakSession keycloakSession, EntityManager entityManager) {
        try {
            if (entityManager == null || !entityManager.isOpen()) {
                logger.info("Reopening EntityManager...");
                return getEntityManager(keycloakSession);
            }
            return entityManager;
        } catch (Exception e) {
            logger.error("Failed to reopen EntityManager: ", e);
            throw new IllegalStateException("Could not reopen EntityManager", e);
        }
    }
}
