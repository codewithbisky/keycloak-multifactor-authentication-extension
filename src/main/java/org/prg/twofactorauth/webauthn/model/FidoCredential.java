package org.prg.twofactorauth.webauthn.model;

import java.util.Objects;
import java.util.UUID;

/**
 * Defines all the information about a FIDO credential associated with a specific user account.
 *
 * @param keyId         the id of key as defined by the FIDO authenticator
 * @param keyType       the fido key type used value set by the authenticator indicates type of public key algo used
 * @param userid        the unique ID in the user database that this credential is associated with
 * @param publicKeyCose the public key encoded in CBOR format see https://datatracker.ietf.org/doc/html/rfc8152
 */


public class FidoCredential {

    private String keyId;
    private String keyType;
    private UUID userid;
    private String publicKeyCose;

    public String getKeyId() {
        return keyId;
    }

    public void setKeyId(String keyId) {
        this.keyId = keyId;
    }

    public UUID getUserid() {
        return userid;
    }

    public void setUserid(UUID userid) {
        this.userid = userid;
    }

    public String getPublicKeyCose() {
        return publicKeyCose;
    }

    public void setPublicKeyCose(String publicKeyCose) {
        this.publicKeyCose = publicKeyCose;
    }

    public String getKeyType() {
        return keyType;
    }

    public void setKeyType(String keyType) {
        this.keyType = keyType;
    }
}