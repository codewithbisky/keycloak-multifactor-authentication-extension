package com.codewithbisky.authentication.extension.webauthn.domain;


import com.codewithbisky.authentication.extension.webauthn.model.FidoCredential;
import com.codewithbisky.authentication.extension.webauthn.model.UserAccount;
import com.yubico.webauthn.CredentialRepository;
import com.yubico.webauthn.RegisteredCredential;
import com.yubico.webauthn.data.ByteArray;
import com.yubico.webauthn.data.PublicKeyCredentialDescriptor;
import com.yubico.webauthn.data.PublicKeyCredentialType;
import com.yubico.webauthn.data.exception.Base64UrlException;
import org.jboss.logging.Logger;

import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

import static com.codewithbisky.authentication.extension.util.JsonUtils.toJson;

public class CredentialRepositoryImpl implements CredentialRepository {
    private static final Logger logger = Logger.getLogger(CredentialRepositoryImpl.class);

    private UserService userService;
    private Optional<UserAccount> userAccount;

    public CredentialRepositoryImpl(UserService userService, Optional<UserAccount> userAccount) {
        this.userService = userService;
        this.userAccount = userAccount;
    }

    @Override
    public Set<PublicKeyCredentialDescriptor> getCredentialIdsForUsername(String username) {

        // in our implementation the usernames are email addresses

        logger.info("CredentialRepositoryImpl _getCredentialIdsForUsername " + username);

        if (userAccount.isPresent()) {

            return userAccount
                    .map(
                            user ->
                                    user.getCredentials().stream()
                                            .map(CredentialRepositoryImpl::toPublicKeyCredentialDescriptor)
                                            .collect(Collectors.toSet()))
                    .orElse(Set.of());
        }
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

        logger.info("CredentialRepositoryImpl getUserHandleForUsername " + username);

        if (userAccount.isPresent()) {
            return userAccount.map(user -> YubicoUtils.toByteArray(UUID.fromString(user.getId())));
        }
        return this.userService.findUserEmail(username)
                .map(user -> {
                    logger.info("CredentialRepositoryImpl getUserHandleForUsername " + toJson(user));
                    return YubicoUtils.toByteArray(UUID.fromString(user.getId()));
                });
    }

    @Override
    public Optional<String> getUsernameForUserHandle(ByteArray userHandle) {

        logger.info("CredentialRepositoryImpl getUsernameForUserHandle " + userHandle);
        if (userHandle.isEmpty()) {
            return Optional.empty();
        }
        if (userAccount.isPresent()) {

            return userAccount
                    .map(userAccount -> userAccount.getEmail());
        }
        return this.userService
                .findUserById(YubicoUtils.toUUID(userHandle).toString())
                .map(userAccount -> userAccount.getEmail());
    }

    @Override
    public Optional<RegisteredCredential> lookup(ByteArray credentialId, ByteArray userHandle) {
        // user can have muliple credentials so we are looking first for the user,
        // then for a credential that matches;
        logger.info("CredentialRepositoryImpl lookup credentialId " + credentialId + " userHandle " + userHandle);
        if (userAccount.isPresent()) {

            return userAccount
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

        logger.info("CredentialRepositoryImpl lookupAll credentialId " + credentialId);
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
