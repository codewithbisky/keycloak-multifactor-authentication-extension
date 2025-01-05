package org.prg.twofactorauth.webauthn.credential;


import org.jboss.logging.Logger;
import org.keycloak.common.util.Time;
import org.keycloak.credential.*;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;

public class WebauthnCredentialProvider implements CredentialProvider<WebAuthnCredentialModel>, CredentialInputValidator {

    private final static Logger logger = Logger.getLogger(WebauthnCredentialProvider.class);
    private final KeycloakSession session;

    public WebauthnCredentialProvider(KeycloakSession session) {
        this.session = session;
    }

    @Override
    public boolean supportsCredentialType(String credentialType) {
        return getType().equals(credentialType);
    }

    @Override
    public boolean isConfiguredFor(RealmModel realm, UserModel user, String credentialType) {

        if (!supportsCredentialType(credentialType)) return false;

        return user.credentialManager().getStoredCredentialsByTypeStream(credentialType).findAny().isPresent();
    }

    @Override
    public boolean isValid(RealmModel realm, UserModel user, CredentialInput input) {
        logger.info("---------------begin valid webauthn");
        return true;
    }

    @Override
    public String getType() {
        return WebAuthnCredentialModel.TYPE;
    }

    @Override
    public CredentialModel createCredential(RealmModel realm,
                                            UserModel user,
                                            WebAuthnCredentialModel credential) {
        if (credential.getCreatedDate() == null) {
            credential.setCreatedDate(Time.currentTimeMillis());
        }
        return user.credentialManager().createStoredCredential(credential);
    }

    @Override
    public boolean deleteCredential(RealmModel realm, UserModel user, String credentialId) {
        return user.credentialManager().removeStoredCredentialById(credentialId);
    }

    @Override
    public WebAuthnCredentialModel getCredentialFromModel(CredentialModel credentialModel) {
        return WebAuthnCredentialModel.createFromCredentialModel(credentialModel);
    }

    @Override
    public CredentialTypeMetadata getCredentialTypeMetadata(CredentialTypeMetadataContext credentialTypeMetadataContext) {
        return CredentialTypeMetadata.builder()
                .type(getType())
                .helpText("")
                .category(CredentialTypeMetadata.Category.TWO_FACTOR)
                .displayName(WebauthnCredentialProviderFactory.PROVIDER_ID)
                .createAction(WebauthnCredentialProviderFactory.PROVIDER_ID)
                .removeable(true)
                .build(session);
    }
}
