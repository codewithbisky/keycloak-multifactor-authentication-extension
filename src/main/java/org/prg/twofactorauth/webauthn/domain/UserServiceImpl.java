package org.prg.twofactorauth.webauthn.domain;

import jakarta.transaction.Transactional;
import org.prg.twofactorauth.webauthn.entity.FidoCredentialEntity;
import org.prg.twofactorauth.webauthn.entity.UserAccountEntity;
import org.prg.twofactorauth.webauthn.model.FidoCredential;
import org.prg.twofactorauth.webauthn.model.UserAccount;

import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

public class UserServiceImpl implements UserService {

//    private final UserAccountRepository userAccountRepository;


    @Override
    @Transactional
    public void addCredential(FidoCredential fidoCredential) {
        FidoCredentialEntity fidoCredentialEntity = new FidoCredentialEntity();
        fidoCredentialEntity.setUserId(fidoCredential.getUserid());
        fidoCredentialEntity.setType(fidoCredential.getKeyType());
        fidoCredentialEntity.setPublicKeyCose(fidoCredential.getPublicKeyCose());
        fidoCredentialEntity.setId(fidoCredential.getKeyId());

//    UserAccountEntity account =
//        this.userAccountRepository
//            .findById(fidoCredential.userid())
//            .orElseThrow(
//                () -> new RuntimeException("can't add a credential to a user that does not exist"));
//    account.getCredentials().add(fidoCredentialEntity);
    }

    @Override
    public Optional<FidoCredential> findCredentialById(String credentialId) {
        return Optional.empty();
    }

    @Override
    public Optional<UserAccount> findUserById(UUID userId) {
//    return this.userAccountRepository.findById(userId).map(UserServiceImpl::toUserAccount);

        UserAccount userAccount=new UserAccount(UUID.randomUUID(),"bisky","marshall",null);
        return Optional.of(userAccount);
    }

    @Override
    public Optional<UserAccount> findUserEmail(String email) {


//        return this.userAccountRepository.findByEmail(email).map(UserServiceImpl::toUserAccount);
    return Optional.empty();
    }

    @Override
    @Transactional
    public UserAccount createOrFindUser(String displayName, String email) {
        if (displayName == null || displayName.isBlank()) {
            throw new IllegalArgumentException("displayName can't be blank");
        }
        if (email == null || email.isBlank()) {
            throw new IllegalArgumentException("email can't be blank");
        }
//
//        UserAccountEntity userAccountEntity =
//                this.userAccountRepository
//                        .findByEmail(email)
//                        .orElseGet(
//                                () -> {
//                                    UserAccountEntity result = new UserAccountEntity();
//                                    result.setEmail(email);
//                                    result.setFullName(displayName);
//                                    return this.userAccountRepository.save(result);
//                                });
//
//        return new UserAccount(
//                userAccountEntity.getId(),
//                userAccountEntity.getFullName(),
//                userAccountEntity.getEmail(),
//                Set.of());
        return null;
    }

    private static UserAccount toUserAccount(UserAccountEntity accountEntity) {

        Set<FidoCredential> credentials =
                accountEntity.getCredentials().stream()
                        .map(
                                c ->
                                        new FidoCredential(
                                                c.getId(), c.getType(),
                                                accountEntity.getId(),
                                                c.getPublicKeyCose()))
                        .collect(Collectors.toSet());

        return new UserAccount(
                accountEntity.getId(), accountEntity.getFullName(), accountEntity.getEmail(), credentials);
    }

}
