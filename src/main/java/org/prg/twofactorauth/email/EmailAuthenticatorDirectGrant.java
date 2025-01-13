package org.prg.twofactorauth.email;

import jakarta.persistence.EntityManager;
import jakarta.persistence.Query;
import jakarta.ws.rs.core.Response;
import lombok.extern.jbosslog.JBossLog;
import org.apache.commons.lang3.StringUtils;
import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.AuthenticationFlowException;
import org.keycloak.authentication.Authenticator;
import org.keycloak.common.util.SecretGenerator;
import org.keycloak.email.EmailException;
import org.keycloak.email.EmailTemplateProvider;
import org.keycloak.events.Errors;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.prg.twofactorauth.TwoFactorOtpStatus;
import org.prg.twofactorauth.TwoFactorType;
import org.prg.twofactorauth.dto.ErrorDto;
import org.prg.twofactorauth.email.entity.TwoFactorOtpEntity;
import org.prg.twofactorauth.webauthn.domain.DbUtil;

import java.util.*;

@JBossLog
public class EmailAuthenticatorDirectGrant implements Authenticator {

    private static final Logger logger = Logger.getLogger(EmailAuthenticatorDirectGrant.class);

    @Override
    public void authenticate(AuthenticationFlowContext context) {

        AuthenticationSessionModel session = context.getAuthenticationSession();
        String userId = session.getAuthenticatedUser().getId();
        String verificationCode = context.getHttpRequest()
                .getDecodedFormParameters()
                .getFirst("verification_code");
        String reference = context.getHttpRequest()
                .getDecodedFormParameters()
                .getFirst("reference");
        UserModel userModel = context.getUser();

        if (StringUtils.isBlank(verificationCode)) {
            context.getEvent().error("verification_code_required");
            Response challengeResponse = this.errorResponse(Response.Status.BAD_REQUEST.getStatusCode(), "verification_code missing");
            context.failure(AuthenticationFlowError.INVALID_USER, challengeResponse);
            return;
        }

        if (StringUtils.isBlank(reference)) {

            context.getEvent().user(userModel).error("reference_required");
            Response challengeResponse = this.errorResponse(Response.Status.BAD_REQUEST.getStatusCode(), "reference missing");
            context.failure(AuthenticationFlowError.INVALID_USER, challengeResponse);
            return;
        }

        Optional<TwoFactorOtpEntity> twoFactorOtpEntity = findTwofactorOtpById(reference, context.getSession());
        if (twoFactorOtpEntity.isEmpty()) {
            context.getEvent().user(userModel).error("reference_not_found");
            Response challengeResponse = this.errorResponse(Response.Status.BAD_REQUEST.getStatusCode(), "reference not found");
            context.failure(AuthenticationFlowError.INVALID_USER, challengeResponse);
            return;
        }
        TwoFactorOtpEntity twoFactorOtpEntity1 = twoFactorOtpEntity.get();
        if(!userId.equals(twoFactorOtpEntity1.getUserId())){
            context.getEvent().user(userModel).error("user_id_mismatch");
            Response challengeResponse = this.errorResponse(Response.Status.BAD_REQUEST.getStatusCode(), "user_id_mismatch");
            context.failure(AuthenticationFlowError.INVALID_USER, challengeResponse);
            return;
        }

        if(twoFactorOtpEntity1.getStatus().equals(TwoFactorOtpStatus.VALID.toString())){
            context.getEvent().user(userModel).error("code_already_used");
            Response challengeResponse = this.errorResponse(Response.Status.BAD_REQUEST.getStatusCode(), "code_already_used");
            context.failure(AuthenticationFlowError.INVALID_USER, challengeResponse);
            return;
        }

        String code = twoFactorOtpEntity1.getCode();
        String ttl = String.valueOf(twoFactorOtpEntity1.getTtl());

        if (verificationCode.equals(code)) {
            if (Long.parseLong(ttl) < System.currentTimeMillis()) {
                // expired
                updateOtpStatus(reference, TwoFactorOtpStatus.EXPIRED, context.getSession());
                context.getEvent().user(userModel).error(Errors.EXPIRED_CODE);
                Response challengeResponse = this.errorResponse(Response.Status.BAD_REQUEST.getStatusCode(), "Code Expired");
                context.failure(AuthenticationFlowError.EXPIRED_CODE, challengeResponse);
            } else {
                // valid
                updateOtpStatus(reference, TwoFactorOtpStatus.VALID, context.getSession());
                context.success();
            }
        } else {
            // invalid
            context.getEvent().user(userModel).error(Errors.INVALID_USER_CREDENTIALS);
            Response challengeResponse = this.errorResponse(Response.Status.UNAUTHORIZED.getStatusCode(), "Invalid Code Supplied");
            context.failure(AuthenticationFlowError.INVALID_CREDENTIALS, challengeResponse);
        }

    }

    @Override
    public void action(AuthenticationFlowContext authenticationFlowContext) {

    }

    public Optional<TwoFactorOtpEntity> findTwofactorOtpById(String id, KeycloakSession keycloakSession) {
        try {
            EntityManager entityManager = DbUtil.getEntityManager(keycloakSession);
            // Using native query to fetch the user account entity
            Query query = entityManager.createNativeQuery(
                    "SELECT * FROM two_factor_otp WHERE id = :id", TwoFactorOtpEntity.class);
            query.setParameter("id", id);
            List<TwoFactorOtpEntity> results = query.getResultList();
            if (results.isEmpty()) {
                return Optional.empty();
            }
            return Optional.of((results.get(0)));
        } catch (Exception e) {
            System.out.println("Error occurred: " + e);
            return Optional.empty();
        }
    }


    public EmailData generateAndSendEmailCode(AuthenticationFlowContext context) {
        AuthenticatorConfigModel config = context.getAuthenticatorConfig();
        AuthenticationSessionModel session = context.getAuthenticationSession();

        int length = EmailConstants.DEFAULT_LENGTH;
        int ttl = EmailConstants.DEFAULT_TTL;
        if (config != null) {
            // get config values
            length =  Integer.parseInt(config.getConfig().get(EmailConstants.CODE_LENGTH));
            ttl = Integer.parseInt(config.getConfig().get(EmailConstants.CODE_TTL));
        }

        String code = SecretGenerator.getInstance().randomString(length, SecretGenerator.DIGITS);
        sendEmailWithCode(context.getSession(), context.getRealm(), context.getUser(), code, ttl);
        session.setAuthNote(EmailConstants.CODE, code);
        session.setAuthNote(EmailConstants.CODE_TTL, Long.toString(System.currentTimeMillis() + (ttl * 1000L)));
        EmailData emailData = new EmailData(UUID.randomUUID().toString(), code, System.currentTimeMillis() + (ttl * 1000L), context.getUser().getId());
        saveTwoFactoOtp(emailData, context.getSession());
        return emailData;
    }


    @Override
    public boolean requiresUser() {
        return true;
    }

    @Override
    public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
        return user.getEmail() != null;
    }

    @Override
    public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {
        // NOOP
    }

    @Override
    public void close() {
        // NOOP
    }

    private void sendEmailWithCode(KeycloakSession session, RealmModel realm, UserModel user, String code, int ttl) {
        if (user.getEmail() == null) {
            log.warnf("Could not send access code email due to missing email. realm=%s user=%s", realm.getId(), user.getUsername());
            throw new AuthenticationFlowException(AuthenticationFlowError.INVALID_USER);
        }

        Map<String, Object> mailBodyAttributes = new HashMap<>();
        mailBodyAttributes.put("username", user.getUsername());
        mailBodyAttributes.put("code", code);
        mailBodyAttributes.put("ttl", ttl);

        String realmName = realm.getDisplayName() != null ? realm.getDisplayName() : realm.getName();
        List<Object> subjectParams = List.of(realmName);
        try {
            EmailTemplateProvider emailProvider = session.getProvider(EmailTemplateProvider.class);
            emailProvider.setRealm(realm);
            emailProvider.setUser(user);
            // Don't forget to add the welcome-email.ftl (html and text) template to your theme.
            emailProvider.send("emailCodeSubject", subjectParams, "code-email.ftl", mailBodyAttributes);
        } catch (EmailException eex) {
            log.errorf(eex, "Failed to send access code email. realm=%s user=%s", realm.getId(), user.getUsername());
        }
    }

    public void saveTwoFactoOtp(EmailData emailData, KeycloakSession session) {
        try {
            EntityManager entityManager = DbUtil.getEntityManager(session);
            // Begin transaction
            entityManager.getTransaction().begin();

            // Execute native SQL insert
            String sql = "INSERT INTO two_factor_otp " +
                    "(id, code, ttl, type, status, user_id) " +
                    "VALUES (:id, :code, :ttl, :type, :status, :user_id)";

            Query query = entityManager.createNativeQuery(sql);
            query.setParameter("id", emailData.reference());
            query.setParameter("code", emailData.code());
            query.setParameter("ttl", emailData.ttl());
            query.setParameter("type", TwoFactorType.email.toString());
            query.setParameter("status", TwoFactorOtpStatus.PENDING.toString());
            query.setParameter("user_id", emailData.userId());
            query.executeUpdate();

            // Commit the transaction
            entityManager.getTransaction().commit();
            // close connection
            entityManager.close();
        } catch (Exception e) {
            logger.error("(saveTwoFactoOtp) Error during save: " + e);
            throw e;
        }
    }

    private Response errorResponse(int statusCode, String invalidUserCredentials) {
        return Response.status(statusCode)
                .entity(new ErrorDto(invalidUserCredentials))
                .build();
    }

    public void updateOtpStatus(String id, TwoFactorOtpStatus status, KeycloakSession keycloakSession) {
        try {
            EntityManager entityManager = DbUtil.getEntityManager(keycloakSession);


            // Native update query to update the RegistrationFlowEntity
            Query query = entityManager.createNativeQuery(
                    "UPDATE two_factor_otp " +
                            "SET status = :status " +
                            "WHERE id = :id");

            // Set parameters for the query
            query.setParameter("status", status.toString());
            query.setParameter("id", id);

            // Execute update
            query.executeUpdate();

            // Commit transaction
            entityManager.getTransaction().commit();
        } catch (Exception e) {
            logger.error("EmailAuthenticatorDirectGrant (updateOtpStatus) Error during native update: " + e.getMessage());
            e.printStackTrace();

        }
    }




    public EmailData generateAndSendEmailCode(KeycloakSession keycloakSession,
                                              UserModel userModel,int length, int ttl) {

        String code = SecretGenerator.getInstance().randomString(length, SecretGenerator.DIGITS);
        sendEmailWithCode(keycloakSession, keycloakSession.getContext().getRealm(), userModel, code, ttl);
        EmailData emailData = new EmailData(UUID.randomUUID().toString(), code, System.currentTimeMillis() + (ttl * 1000L), userModel.getId());
        saveTwoFactoOtp(emailData, keycloakSession);
        return emailData;
    }
}
