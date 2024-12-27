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
import java.util.UUID;
import java.util.stream.Collectors;

public class CredentialRepositoryImpl implements CredentialRepository {

    private  UserService userService;

    public CredentialRepositoryImpl(UserService userService) {
        this.userService = userService;
    }

    @Override
    public Set<PublicKeyCredentialDescriptor> getCredentialIdsForUsername(String username) {

        // in our implementation the usernames are email addresses


        return this.userService
                .findUserEmail(username)
                .map(
                        user ->
                                user.getCredentials().stream()
                                        .map(CredentialRepositoryImpl::toPublicKeyCredentialDescriptor)
                                        .collect(Collectors.toSet()))
                .orElse(Set.of());
    }

    @Override
    public Optional<ByteArray> getUserHandleForUsername(String username) {

        return this.userService.findUserEmail(username).map(user -> YubicoUtils.toByteArray(UUID.fromString(user.getId())));
    }

    @Override
    public Optional<String> getUsernameForUserHandle(ByteArray userHandle) {
        if (userHandle.isEmpty()) {
            return Optional.empty();
        }
        return this.userService
                .findUserById(YubicoUtils.toUUID(userHandle).toString())
                .map(userAccount -> userAccount.getEmail());
    }

    @Override
    public Optional<RegisteredCredential> lookup(ByteArray credentialId, ByteArray userHandle) {
        // user can have muliple credentials so we are looking first for the user,
        // then for a credential that matches;

        return this.userService
                .findUserById(YubicoUtils.toUUID(userHandle).toString())
                .map(user -> user.getCredentials())
                .orElse(Set.of())
                .stream()
                .filter(
                        cred -> {
                            try {
                                return credentialId.equals(ByteArray.fromBase64Url(cred.getKeyId()));
                            } catch (Base64UrlException e) {
                                throw new RuntimeException(e);
                            }
                        })
                .findFirst()
                .map(CredentialRepositoryImpl::toRegisteredCredential);
    }

    @Override
    public Set<RegisteredCredential> lookupAll(ByteArray credentialId) {

        return Set.of();
    }

    private static RegisteredCredential toRegisteredCredential(FidoCredential fidoCredential) {
        try {
            return RegisteredCredential.builder()
                    .credentialId(ByteArray.fromBase64Url(fidoCredential.getKeyId()))
                    .userHandle(YubicoUtils.toByteArray(UUID.fromString(fidoCredential.getUserid())))
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
