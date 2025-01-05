package org.prg.twofactorauth.webauthn.credential;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;
import org.jboss.logging.Logger;
import org.keycloak.common.util.Time;
import org.keycloak.credential.CredentialModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.credential.dto.OTPSecretData;
import org.keycloak.util.JsonSerialization;
import org.prg.twofactorauth.webauthn.entity.FidoCredentialEntity;

import java.io.IOException;
import java.util.Date;
import java.util.Optional;

public class WebAuthnCredentialModel extends CredentialModel {

    private final static Logger logger = Logger.getLogger(WebAuthnCredentialModel.class);

    public static final String TYPE = "custom-webauthn";
    private final WebauthnCredentialData credentialData;
    private final OTPSecretData secretData;

    public WebAuthnCredentialModel(WebauthnCredentialData credentialData, OTPSecretData secretData) {
        this.credentialData = credentialData;
        this.secretData = secretData;
    }

    private static Optional<CredentialModel> getWebauthnCredentialModel(UserModel user) {
        return user.credentialManager()
                .getStoredCredentialsByTypeStream(WebAuthnCredentialModel.TYPE).findFirst();
    }

    public static Optional<WebAuthnCredentialModel.WebauthnCredentialData> getWebauthnCredentialData(UserModel user) {
        return getWebauthnCredentialModel(user)
                .map(credentialModel -> {
                    try {
                        return JsonSerialization.readValue(credentialModel.getCredentialData(), WebAuthnCredentialModel.WebauthnCredentialData.class);
                    } catch (IOException e) {
                        throw new IllegalArgumentException(e);
                    }
                });
    }

    public static void updateWebauthCredential(UserModel user,
                                               WebAuthnCredentialModel.WebauthnCredentialData credentialData,
                                               String secretValue) {
        getWebauthnCredentialModel(user)
                .ifPresent(credential -> {
                    try {
                        credential.setCredentialData(JsonSerialization.writeValueAsString(credentialData));
                        credential.setSecretData(JsonSerialization.writeValueAsString(new OTPSecretData(secretValue)));
                        WebAuthnCredentialModel credentialModel = WebAuthnCredentialModel.createFromCredentialModel(credential);
                        user.credentialManager().updateStoredCredential(credentialModel);
                    } catch (IOException ioe) {
                        logger.error("Failed to update credential", ioe);
                        throw new RuntimeException(ioe);
                    }
                });
    }

    public static WebAuthnCredentialModel create(String secretValue, FidoCredentialEntity fidoCredentialEntity) {
        WebauthnCredentialData credentialData = new WebauthnCredentialData(fidoCredentialEntity.getId(), fidoCredentialEntity.getType(), fidoCredentialEntity.getPublicKeyCose());
        OTPSecretData secretData = new OTPSecretData(secretValue);
        WebAuthnCredentialModel credentialModel = new WebAuthnCredentialModel(credentialData, secretData);
        credentialModel.fillCredentialModelFields();
        return credentialModel;
    }

    public static WebAuthnCredentialModel createFromCredentialModel(CredentialModel credentialModel) {

        try {
            WebauthnCredentialData credentialData = JsonSerialization.readValue(credentialModel.getCredentialData(), WebauthnCredentialData.class);
            OTPSecretData secretData = JsonSerialization.readValue(credentialModel.getSecretData(), OTPSecretData.class);
            WebAuthnCredentialModel credential = new WebAuthnCredentialModel(credentialData, secretData);

            credential.setUserLabel(credentialModel.getUserLabel());
            credential.setCreatedDate(credentialModel.getCreatedDate());
            credential.setType(TYPE);
            credential.setId(credentialModel.getId());
            credential.setSecretData(credentialModel.getSecretData());
            credential.setCredentialData(credentialModel.getCredentialData());

            return credential;
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    private void fillCredentialModelFields() {
        try {
            setCredentialData(JsonSerialization.writeValueAsString(credentialData));
            setSecretData(JsonSerialization.writeValueAsString(secretData));
            setType(TYPE);
            setCreatedDate(Time.currentTimeMillis());
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    public WebauthnCredentialData getWebauthnCredentialData() {
        return credentialData;
    }

    public OTPSecretData getWebauthnSecretData() {
        return secretData;
    }


    public static class WebauthnCredentialData {
        private final String keyId;
        private final String keyType;
        private final long secretCreate;
        private final String publicKeyCose;


        @JsonCreator
        public WebauthnCredentialData(@JsonProperty("keyId") String keyId,
                                      @JsonProperty("keyType") String keyType,
                                      @JsonProperty("publicKeyCose") String publicKeyCose
        ) {
            this.keyId = keyId;
            this.keyType = keyType;
            this.secretCreate = new Date().getTime();
            this.publicKeyCose = publicKeyCose;
        }

        public String getKeyId() {
            return keyId;
        }

        public String getKeyType() {
            return keyType;
        }

        public long getSecretCreate() {
            return secretCreate;
        }

        public String getPublicKeyCose() {
            return publicKeyCose;
        }
    }

    public static class EmptySecretData {
    }
}
