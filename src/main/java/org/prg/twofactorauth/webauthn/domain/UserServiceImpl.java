package org.prg.twofactorauth.webauthn.domain;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.yubico.webauthn.*;
import com.yubico.webauthn.data.*;
import com.yubico.webauthn.exception.AssertionFailedException;
import com.yubico.webauthn.exception.RegistrationFailedException;
import jakarta.persistence.EntityManager;
import jakarta.persistence.Query;
import jakarta.transaction.Transactional;
import org.jboss.logging.Logger;
import org.keycloak.credential.CredentialProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.UserModel;
import org.prg.twofactorauth.dto.*;
import org.prg.twofactorauth.util.JsonUtils;
import org.prg.twofactorauth.webauthn.credential.WebAuthnCredentialModel;
import org.prg.twofactorauth.webauthn.credential.WebauthnCredentialProvider;
import org.prg.twofactorauth.webauthn.credential.WebauthnCredentialProviderFactory;
import org.prg.twofactorauth.webauthn.entity.FidoCredentialEntity;
import org.prg.twofactorauth.webauthn.entity.LoginFlowEntity;
import org.prg.twofactorauth.webauthn.entity.RegistrationFlowEntity;
import org.prg.twofactorauth.webauthn.entity.UserAccountEntity;
import org.prg.twofactorauth.webauthn.model.FidoCredential;
import org.prg.twofactorauth.webauthn.model.UserAccount;

import java.io.IOException;
import java.util.*;
import java.util.stream.Collectors;

import static org.prg.twofactorauth.util.JsonUtils.toJson;
import static org.prg.twofactorauth.webauthn.domain.RelyingPartyConfiguration.relyingParty;

public class UserServiceImpl implements UserService {
    private static final Logger logger = Logger.getLogger(UserServiceImpl.class);

    private final KeycloakSession keycloakSession;
    private final UserModel user;
    private EntityManager entityManager;

    public UserServiceImpl(KeycloakSession keycloakSession, UserModel user, EntityManager entityManager) {
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
        WebauthnCredentialProvider ocp = (WebauthnCredentialProvider) keycloakSession
                .getProvider(CredentialProvider.class, WebauthnCredentialProviderFactory.PROVIDER_ID);
        ocp.createCredential(keycloakSession.getContext().getRealm(), user, WebAuthnCredentialModel.create(fidoCredential.getKeyId(),fidoCredentialEntity));
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
        try {
            entityManager = DbUtil.getOrReopenEntityManager(keycloakSession,entityManager);
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

        try {
            entityManager = DbUtil.getOrReopenEntityManager(keycloakSession,entityManager);
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
            logger.error("(findUserEmail) Error occurred: " + e);
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

        try {
            entityManager = DbUtil.getOrReopenEntityManager(keycloakSession,entityManager);
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
            logger.error("(saveUserAccount) Error during native insert: " + e);
        }
        return null;
    }

    private UserAccount toUserAccount(UserAccountEntity accountEntity) {


        List<FidoCredentialEntity> credentialsByUserId = findCredentialsByUserId(accountEntity.getId());
        Set<FidoCredentialEntity> set = new HashSet<>(credentialsByUserId);
        Set<FidoCredential> credentials =
                set.stream()
                        .map(
                                c ->
                                        new FidoCredential(
                                                c.getId(),
                                                c.getType(),
                                                c.getUserId(),
                                                c.getPublicKeyCose()))
                        .collect(Collectors.toSet());

        return new UserAccount(
                accountEntity.getId(), accountEntity.getFullName(), accountEntity.getEmail(), credentials);
    }


    public void insertRegistrationFlow(RegistrationFlowEntity registrationFlowEntity) {
        try {
            entityManager = DbUtil.getOrReopenEntityManager(keycloakSession,entityManager);
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
            logger.error("(insertRegistrationFlow) Error during native insert: " + e.getMessage());
            e.printStackTrace();

        }
    }

    @Override
    public RegistrationFinishResponse finishRegistration(RegistrationFinishRequest finishRequest) throws RegistrationFailedException, IOException {


        RegistrationFlowEntity invalidFlow = findRegistrationFlowById(finishRequest.getReference()).orElseThrow(() -> new RuntimeException("Invalid flow"));
        PublicKeyCredentialCreationOptions credentialCreationOptions = PublicKeyCredentialCreationOptions.fromJson(invalidFlow.getRegistrationResult());
        String string = finishRequest.getCredential();
        Object parsed = JsonUtils.mapper.readValue(string, Object.class);

        String string1 = JsonUtils.mapper.writerWithDefaultPrettyPrinter().writeValueAsString(parsed);
        PublicKeyCredential<AuthenticatorAttestationResponse, ClientRegistrationExtensionOutputs> pkc = null;

        try {
            pkc = PublicKeyCredential.parseRegistrationResponseJson(string1);

        } catch (Exception e) {
            logger.error("parseRegistrationResponseJson ",e);
            throw e;
        }
        FinishRegistrationOptions options =
                FinishRegistrationOptions.builder()
                        .request(credentialCreationOptions)
                        .response(pkc)
                        .build();

        RegistrationResult registrationResult = relyingParty(this,null).finishRegistration(options);

        var fidoCredential =
                new FidoCredential(
                        registrationResult.getKeyId().getId().getBase64Url(),
                        registrationResult.getKeyId().getType().name(),
                        YubicoUtils.toUUID(credentialCreationOptions.getUser().getId()).toString(),
                        registrationResult.getPublicKeyCose().getBase64Url());

        addCredential(fidoCredential);

        RegistrationFinishResponse registrationFinishResponse = new RegistrationFinishResponse();
        registrationFinishResponse.setFlowId(finishRequest.getReference());
        registrationFinishResponse.setRegistrationComplete(true);
        logFinishStep(finishRequest, registrationResult, registrationFinishResponse);
        return registrationFinishResponse;
    }

    private void logFinishStep(
            RegistrationFinishRequest finishRequest,
            RegistrationResult registrationResult,
            RegistrationFinishResponse registrationFinishResponse) {
        RegistrationFlowEntity registrationFlow =
                findRegistrationFlowById(finishRequest.getReference())
                        .orElseThrow(
                                () ->
                                        new RuntimeException(
                                                "Cloud not find a registration flow with id: "
                                                        + finishRequest.getReference()));
        registrationFlow.setFinishRequest(toJson(finishRequest));
        registrationFlow.setFinishResponse(toJson(registrationFinishResponse));
        registrationFlow.setRegistrationResult(toJson(registrationResult));
        updateRegistrationFlow(registrationFlow, toJson(finishRequest), toJson(registrationFinishResponse), toJson(registrationResult));
    }

    public Optional<RegistrationFlowEntity> findRegistrationFlowById(String userId) {
        try {
            entityManager = DbUtil.getOrReopenEntityManager(keycloakSession,entityManager);
            // Using native query to fetch the user account entity
            Query query = entityManager.createNativeQuery(
                    "SELECT * FROM webauthn_registration_flow WHERE id = :id", RegistrationFlowEntity.class);
            query.setParameter("id", userId);
            List<RegistrationFlowEntity> results = query.getResultList();
            if (results.isEmpty()) {
                return Optional.empty();
            }
            return Optional.of(results.get(0));
        } catch (Exception e) {
            logger.error("Error occurred: " + e);
            return Optional.empty();
        }
    }

    public void updateRegistrationFlow(RegistrationFlowEntity registrationFlow, String finishRequest,
                                       String registrationFinishResponse, String registrationResult) {
        try {
            entityManager = DbUtil.getOrReopenEntityManager(keycloakSession,entityManager);
            // Update the entity with new JSON string values
            registrationFlow.setFinishRequest(toJson(finishRequest));
            registrationFlow.setFinishResponse(toJson(registrationFinishResponse));
            registrationFlow.setRegistrationResult(toJson(registrationResult));

            // Native update query to update the RegistrationFlowEntity
            Query query = entityManager.createNativeQuery(
                    "UPDATE webauthn_registration_flow " +
                            "SET finish_request = :finishRequest, finish_response = :finishResponse, " +
                            "yubico_reg_result = :registrationResult " +
                            "WHERE id = :id");

            // Set parameters for the query
            query.setParameter("finishRequest", registrationFlow.getFinishRequest());
            query.setParameter("finishResponse", registrationFlow.getFinishResponse());
            query.setParameter("registrationResult", registrationFlow.getRegistrationResult());
            query.setParameter("id", registrationFlow.getId());

            // Execute update
            query.executeUpdate();

            // Commit transaction
            entityManager.getTransaction().commit();
        } catch (Exception e) {
            logger.error("(updateRegistrationFlow) Error during native update: " + e.getMessage());
            e.printStackTrace();

        }
    }

    public List<FidoCredentialEntity> findCredentialsByUserId(String userId) {
        try {
            entityManager = DbUtil.getOrReopenEntityManager(keycloakSession,entityManager);
            // Using native query to fetch the user account entity
            Query query = entityManager.createNativeQuery(
                    "SELECT * FROM webauthn_user_credentials WHERE user_id = :userId", FidoCredentialEntity.class);
            query.setParameter("userId", userId);
            List<FidoCredentialEntity> results = query.getResultList();
            if (results.isEmpty()) {
                return new ArrayList<>();
            }
            return results;
        } catch (Exception e) {
            logger.error("(findCredentialsByUserId) Error occurred: " + e);
            return new ArrayList<>();
        }
    }


    @Transactional
    public LoginStartResponse startLogin(LoginStartRequest loginStartRequest) throws JsonProcessingException {

        // Find the user in the user database
        UserAccount user =
                findUserEmail(loginStartRequest.getEmail())
                        .orElseThrow(() -> new RuntimeException("Email does not exist"));

        // make the assertion request to send to the client
        StartAssertionOptions options =
                StartAssertionOptions.builder()
                        .timeout(60_000)
                        .username(loginStartRequest.getEmail())
//                             .userHandle(YubicoUtils.toByteArray(UUID.fromString(user.getId())))
                        .build();
        AssertionRequest assertionRequest = relyingParty(this,user).startAssertion(options);

        LoginStartResponse loginStartResponse = new LoginStartResponse();
        loginStartResponse.setReference(UUID.randomUUID().toString());
        loginStartResponse.setAssertionRequest(assertionRequest);

        LoginFlowEntity loginFlowEntity = new LoginFlowEntity();
        loginFlowEntity.setId(loginStartResponse.getReference());
        loginFlowEntity.setStartRequest(toJson(loginStartRequest));
        loginFlowEntity.setStartResponse(toJson(loginStartResponse));
        loginFlowEntity.setUsername(loginStartRequest.getEmail());
        loginFlowEntity.setAssertionRequest(assertionRequest.toJson());
        saveLoginFlowEntityNative(loginFlowEntity);
        return loginStartResponse;
    }

    public void saveLoginFlowEntityNative(LoginFlowEntity loginFlowEntity) {
        try {
            entityManager = DbUtil.getOrReopenEntityManager(keycloakSession,entityManager);
            // Begin transaction
            entityManager.getTransaction().begin();

            // Execute native SQL insert
            String sql = "INSERT INTO webauthn_login_flow " +
                    "(id, start_request, start_response, successful_login, assertion_request, assertion_result, user_name) " +
                    "VALUES (:id, :startRequest, :startResponse, :successfulLogin, :assertionRequest, :assertionResult, :username)";

            Query query = entityManager.createNativeQuery(sql);
            query.setParameter("id", loginFlowEntity.getId());
            query.setParameter("startRequest", loginFlowEntity.getStartRequest());
            query.setParameter("startResponse", loginFlowEntity.getStartResponse());
            query.setParameter("successfulLogin", loginFlowEntity.getSuccessfulLogin());
            query.setParameter("assertionRequest", loginFlowEntity.getAssertionRequest());
            query.setParameter("assertionResult", loginFlowEntity.getAssertionResult());
            query.setParameter("username", loginFlowEntity.getUsername());

            query.executeUpdate();

            // Commit the transaction
            entityManager.getTransaction().commit();
        } catch (Exception e) {
            logger.error("(saveLoginFlowEntityNative) Error during save: " + e);
        }
    }

    public Optional<LoginFlowEntity> findLoginFlowById(String userId) {
        try {
            entityManager = DbUtil.getOrReopenEntityManager(keycloakSession,entityManager);
            // Using native query to fetch the user account entity
            Query query = entityManager.createNativeQuery(
                    "SELECT * FROM webauthn_login_flow WHERE id = :id", LoginFlowEntity.class);
            query.setParameter("id", userId);
            List<LoginFlowEntity> results = query.getResultList();
            if (results.isEmpty()) {
                return Optional.empty();
            }
            return Optional.of(results.get(0));
        } catch (Exception e) {
            logger.error("Error occurred: " + e);
            return Optional.empty();
        }
    }

    @Transactional
    public Map<String, Object> finishLogin(LoginFinishRequest loginFinishRequest) throws IOException, AssertionFailedException {

        var loginFlowEntity =
                findLoginFlowById(loginFinishRequest.getFlowId())
                        .orElseThrow(
                                () ->
                                        new RuntimeException(
                                                "flow id " + loginFinishRequest.getFlowId() + " not found"));


        var assertionRequestJson = loginFlowEntity.getAssertionRequest();
        AssertionRequest assertionRequest;
        assertionRequest = AssertionRequest.fromJson(assertionRequestJson);
        String string = loginFinishRequest.getCredential();
        Object parsed = JsonUtils.mapper.readValue(string, Object.class);

        String string1 = JsonUtils.mapper.writerWithDefaultPrettyPrinter().writeValueAsString(parsed);
        PublicKeyCredential<AuthenticatorAssertionResponse, ClientAssertionExtensionOutputs>
        pkc = PublicKeyCredential.parseAssertionResponseJson(string1);
        FinishAssertionOptions options =
                FinishAssertionOptions.builder()
                        .request(assertionRequest)
                        .response(pkc)
                        .build();

        String userName = loginFlowEntity.getUsername();
        UserAccount userAccount = findUserEmail(userName).orElseThrow();
        AssertionResult assertionResult = relyingParty(this,userAccount).finishAssertion(options);
        loginFlowEntity.setAssertionResult(toJson(assertionResult));
        loginFlowEntity.setSuccessfulLogin(assertionResult.isSuccess());
        updateLoginFlowEntityNative(loginFlowEntity.getId(), loginFlowEntity.getAssertionResult(), loginFlowEntity.getSuccessfulLogin());
        Map<String, Object> results = new HashMap<>();
        if (assertionResult.isSuccess()) {
            results.put("success", true);
        }
        return results;
    }

    public void updateLoginFlowEntityNative(String id, String assertionResult, boolean successfulLogin) {
        try {
            entityManager = DbUtil.getOrReopenEntityManager(keycloakSession,entityManager);
            // Begin transaction
            entityManager.getTransaction().begin();

            // Execute native SQL update
            String sql = "UPDATE webauthn_login_flow " +
                    "SET assertion_result = :assertionResult, successful_login = :successfulLogin " +
                    "WHERE id = :id";

            Query query = entityManager.createNativeQuery(sql);
            query.setParameter("id", id);
            query.setParameter("assertionResult", assertionResult);
            query.setParameter("successfulLogin", successfulLogin);

            query.executeUpdate();

            // Commit the transaction
            entityManager.getTransaction().commit();
        } catch (Exception e) {
            logger.error("(updateLoginFlowEntityNative) Error during update: " + e);

        }
    }

    public boolean webAuthnConfigured() {

        return  getCredentialProvider(keycloakSession).isConfiguredFor(keycloakSession.getContext().getRealm(), user, WebAuthnCredentialModel.TYPE);
    }

    public WebauthnCredentialProvider getCredentialProvider(KeycloakSession keycloakSession) {
        return (WebauthnCredentialProvider) keycloakSession.getProvider(CredentialProvider.class, WebauthnCredentialProviderFactory.PROVIDER_ID);

    }
}
