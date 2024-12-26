package org.prg.twofactorauth.webauthn.domain;


import com.yubico.webauthn.CredentialRepository;
import com.yubico.webauthn.RegisteredCredential;
import com.yubico.webauthn.data.ByteArray;
import com.yubico.webauthn.data.PublicKeyCredentialDescriptor;
import com.yubico.webauthn.data.PublicKeyCredentialType;
import com.yubico.webauthn.data.exception.Base64UrlException;
import org.prg.twofactorauth.webauthn.model.FidoCredential;

import java.util.Optional;
import java.util.Set;


public class CredentialRepositoryImpl implements CredentialRepository {


    @Override
    public Set<PublicKeyCredentialDescriptor> getCredentialIdsForUsername(String username) {

        // in our implementation the usernames are email addresses

        return null;
    }

    @Override
    public Optional<ByteArray> getUserHandleForUsername(String username) {

        return null;
    }

    @Override
    public Optional<String> getUsernameForUserHandle(ByteArray userHandle) {
        if (userHandle.isEmpty()) {
            return Optional.empty();
        }
        return null;
    }

    @Override
    public Optional<RegisteredCredential> lookup(ByteArray credentialId, ByteArray userHandle) {
        // user can have muliple credentials so we are looking first for the user,
        // then for a credential that matches;

        return null;
    }

    @Override
    public Set<RegisteredCredential> lookupAll(ByteArray credentialId) {

        return null;
    }

    private static RegisteredCredential toRegisteredCredential(FidoCredential fidoCredential) {
        try {
            return RegisteredCredential.builder()
                    .credentialId(ByteArray.fromBase64Url(fidoCredential.getKeyId()))
                    .userHandle(YubicoUtils.toByteArray(fidoCredential.getUserid()))
                    .publicKeyCose(ByteArray.fromBase64Url(fidoCredential.getPublicKeyCose()))
                    .build();
        } catch (Base64UrlException e) {
            throw new RuntimeException(e);
        }
    }

    private static PublicKeyCredentialDescriptor toPublicKeyCredentialDescriptor(FidoCredential cred) {
        PublicKeyCredentialDescriptor descriptor = null;
        try {
            return PublicKeyCredentialDescriptor.builder()
                    .id(ByteArray.fromBase64Url(cred.getKeyId()))
                    .type(PublicKeyCredentialType.valueOf(cred.getKeyType()))
                    .build();

        } catch (Base64UrlException e) {
            throw new RuntimeException(e);
        }
    }
}
