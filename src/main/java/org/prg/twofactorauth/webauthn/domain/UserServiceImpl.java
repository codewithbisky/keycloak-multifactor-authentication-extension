package org.prg.twofactorauth.webauthn.domain;

import jakarta.persistence.EntityManager;
import jakarta.persistence.Query;
import jakarta.transaction.Transactional;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.UserModel;
import org.prg.twofactorauth.webauthn.entity.FidoCredentialEntity;
import org.prg.twofactorauth.webauthn.entity.RegistrationFlowEntity;
import org.prg.twofactorauth.webauthn.entity.UserAccountEntity;
import org.prg.twofactorauth.webauthn.model.FidoCredential;
import org.prg.twofactorauth.webauthn.model.UserAccount;

import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

public class UserServiceImpl implements UserService {

    private final KeycloakSession keycloakSession;
    private final UserModel user;
    private final EntityManager entityManager;
    public UserServiceImpl(KeycloakSession keycloakSession,UserModel user,EntityManager entityManager) {
        this.keycloakSession = keycloakSession;
        this.user = user;
        this.entityManager = entityManager;
    }

    @Override
    @Transactional
    public void addCredential(FidoCredential fidoCredential) {
        FidoCredentialEntity fidoCredentialEntity = new FidoCredentialEntity();
        fidoCredentialEntity.setUserId(fidoCredential.getUserid());
        fidoCredentialEntity.setType(fidoCredential.getKeyType());
        fidoCredentialEntity.setPublicKeyCose(fidoCredential.getPublicKeyCose());
        fidoCredentialEntity.setId(fidoCredential.getKeyId());
        Optional<UserAccount> optionalUserAccount = findUserById(fidoCredential.getUserid());
        if (optionalUserAccount.isEmpty()) {
            throw new RuntimeException("can't add a credential to a user that does not exist");
        }
        insertFidoCredential(fidoCredentialEntity);
    }

    public void insertFidoCredential(FidoCredentialEntity fidoCredentialEntity) {
        try {
            entityManager.getTransaction().begin();

            // Native insert query
            Query query = entityManager.createNativeQuery(
                    "INSERT INTO webauthn_user_credentials (id, user_id, type, public_key_cose) VALUES (:id, :userId, :type, :publicKeyCose)");

            // Set parameters for the query
            query.setParameter("id", fidoCredentialEntity.getId());
            query.setParameter("userId", fidoCredentialEntity.getUserId());
            query.setParameter("type", fidoCredentialEntity.getType());
            query.setParameter("publicKeyCose", fidoCredentialEntity.getPublicKeyCose());

            // Execute update
            query.executeUpdate();

            // Commit transaction
            entityManager.getTransaction().commit();
        } catch (Exception e) {
            System.out.println("(insertFidoCredential) Error during native insert: " + e);
        }
    }


    @Override
    public Optional<FidoCredential> findCredentialById(String credentialId) {
        return Optional.empty();
    }

    @Override
    public Optional<UserAccount> findUserById(String userId) {
        try  {
            // Using native query to fetch the user account entity
            Query query = entityManager.createNativeQuery(
                    "SELECT * FROM webauth_user_accounts WHERE id = :id", UserAccountEntity.class);
            query.setParameter("id", userId);
            List<UserAccountEntity> results = query.getResultList();
            if (results.isEmpty()) {
                return Optional.empty();
            }
            return Optional.of(toUserAccount(results.get(0)));
        } catch (Exception e) {
            System.out.println("Error occurred: " + e);
            return Optional.empty();
        }
    }


    @Override
    public Optional<UserAccount> findUserEmail(String email) {

        try  {
            // Using native query to fetch the user account entity
            Query query = entityManager.createNativeQuery(
                    "SELECT * FROM webauth_user_accounts WHERE email = :email", UserAccountEntity.class);
            query.setParameter("email", email);
            List<UserAccountEntity> results = query.getResultList();
            if (results.isEmpty()) {
                return Optional.empty();
            }
            return Optional.of(toUserAccount(results.get(0)));
        } catch (Exception e) {
            System.out.println("Error occurred: " + e);
            return Optional.empty();
        }
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

        UserAccount userAccountEntity =
                findUserEmail(email)
                        .orElseGet(
                                () -> {
                                    UserAccountEntity result = new UserAccountEntity();
                                    result.setEmail(email);
                                    result.setFullName(displayName);
                                    result.setId(user.getId());
                                    return saveUserAccount(result);
                                });

        return new UserAccount(
                userAccountEntity.getId(),
                userAccountEntity.getDisplayName(),
                userAccountEntity.getEmail(),
                Set.of());
    }

    private UserAccount saveUserAccount(UserAccountEntity result) {

        try (EntityManager entityManager = DbUtil.getEntityManager(keycloakSession)) {
            entityManager.getTransaction().begin();

            // Native insert query
            Query query = entityManager.createNativeQuery(
                    "INSERT INTO webauth_user_accounts (id, full_name, email) VALUES (:id, :fullName, :email)");

            // Set parameters for the query
            query.setParameter("id", result.getId());
            query.setParameter("fullName", result.getFullName());
            query.setParameter("email", result.getEmail());

            // Execute update
            query.executeUpdate();

            // Commit transaction
            entityManager.getTransaction().commit();

            return findUserById(result.getId()).get();
        } catch (Exception e) {
            System.out.println("(saveUserAccount) Error during native insert: " + e);
        }
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



    public void insertRegistrationFlow(RegistrationFlowEntity registrationFlowEntity) {
        try {
            entityManager.getTransaction().begin(); // Start transaction
            // Native insert query
            Query query = entityManager.createNativeQuery(
                    "INSERT INTO webauthn_registration_flow " +
                            "(id, start_request, start_response, finish_request, finish_response, yubico_reg_result, yubico_creation_options) " +
                            "VALUES (:id, :startRequest, :startResponse, :finishRequest, :finishResponse, :registrationResult, :creationOptions)");

            // Set parameters for the query
            query.setParameter("id", registrationFlowEntity.getId());
            query.setParameter("startRequest", registrationFlowEntity.getStartRequest());
            query.setParameter("startResponse", registrationFlowEntity.getStartResponse());
            query.setParameter("finishRequest", registrationFlowEntity.getFinishRequest());
            query.setParameter("finishResponse", registrationFlowEntity.getFinishResponse());
            query.setParameter("registrationResult", registrationFlowEntity.getRegistrationResult());
            query.setParameter("creationOptions", registrationFlowEntity.getCreationOptions());

            // Execute update
            query.executeUpdate();

            // Commit transaction
            entityManager.getTransaction().commit();
        } catch (Exception e) {
            System.out.println("(insertRegistrationFlow) Error during native insert: " + e.getMessage());
            e.printStackTrace();

        }
    }
}
