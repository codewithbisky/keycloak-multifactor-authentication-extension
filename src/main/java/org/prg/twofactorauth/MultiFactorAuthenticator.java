package org.prg.twofactorauth;

import jakarta.ws.rs.core.Response;
import org.apache.commons.lang3.StringUtils;
import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.FlowStatus;
import org.keycloak.authentication.authenticators.directgrant.ValidateOTP;
import org.keycloak.credential.CredentialProvider;
import org.keycloak.credential.OTPCredentialProvider;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.prg.twofactorauth.dto.EmailReferenceResponse;
import org.prg.twofactorauth.dto.ErrorDto;
import org.prg.twofactorauth.email.EmailAuthenticatorDirectGrant;
import org.prg.twofactorauth.email.EmailAuthenticatorDirectGrantFactory;
import org.prg.twofactorauth.email.EmailData;
import org.prg.twofactorauth.webauthn.WebAuthn2MFAAuthenticator;
import org.prg.twofactorauth.webauthn.credential.WebAuthnCredentialModel;
import org.prg.twofactorauth.webauthn.credential.WebauthnCredentialProvider;
import org.prg.twofactorauth.webauthn.credential.WebauthnCredentialProviderFactory;

import java.util.List;
import java.util.Objects;

import static org.prg.twofactorauth.MultiFactorAuthenticatorFactory.ENABLE_EMAIL_2ND_AUTHENTICATION;
import static org.prg.twofactorauth.util.KeycloakSessionUtil.getUserSupportedMfa;
import static org.prg.twofactorauth.util.ProvidersUtil.*;

public class MultiFactorAuthenticator implements Authenticator {

    private static final Logger logger = Logger.getLogger(MultiFactorAuthenticator.class);

    @Override
    public void authenticate(AuthenticationFlowContext context) {

        UserModel user = context.getUser();
        List<String> userSupportedMfa = getUserSupportedMfa(user, context.getSession());
        if (userSupportedMfa.isEmpty()) {
            context.success();
        } else {

            boolean isOtpConfigured =
                    ((OTPCredentialProvider) getCredentialProvider(
                            context.getSession(), "keycloak-otp"))
                            .isConfiguredFor(context.getRealm(), user, "otp");

            boolean isWebAuthnConfigured = getWebauthnCredentialProvider(
                    context.getSession())
                    .isConfiguredFor(context.getRealm(), user,
                            WebAuthnCredentialModel.TYPE);

            String twoFactorType = context.getHttpRequest()
                    .getDecodedFormParameters()
                    .getFirst("2nd_factor_type");
            if (StringUtils.isBlank(twoFactorType)) {
                Response challengeResponse = this.errorResponse(Response.Status.UNAUTHORIZED.getStatusCode(),
                        "2nd_factor_type missing");
                context.failure(AuthenticationFlowError.INVALID_USER, challengeResponse);
            } else if (Objects.equals(TwoFactorType.otp.toString(), twoFactorType) && isOtpConfigured) {
                boolean isValid = validateOtp(context);
                if (isValid) {
                    context.success();
                }
            } else if (Objects.equals(TwoFactorType.webauthn.toString(), twoFactorType) && isWebAuthnConfigured) {
                boolean isValid = validateWebAuthn(context);
                if (isValid) {
                    context.success();
                }
            } else if (Objects.equals(TwoFactorType.email.toString(), twoFactorType)) {
                boolean isValid = validateEmail(context);
                if (isValid) {
                    context.success();
                }
            } else {
                Response challengeResponse = this.errorResponse(Response.Status.UNAUTHORIZED.getStatusCode(),
                        "2nd_authentication_required "+userSupportedMfa);
                context.failure(AuthenticationFlowError.INVALID_USER, challengeResponse);
            }
        }
    }


    private boolean validateEmail(AuthenticationFlowContext context) {
        EmailAuthenticatorDirectGrant emailAuthenticatorProvider = getEmailAuthenticatorProvider(context.getSession());
        String verificationCode = context.getHttpRequest()
                .getDecodedFormParameters()
                .getFirst("verification_code");
        String reference = context.getHttpRequest()
                .getDecodedFormParameters()
                .getFirst("reference");
        if (StringUtils.isBlank(verificationCode)) {
            Response challengeResponse = this.errorResponse(Response.Status.UNAUTHORIZED.getStatusCode(),
                    "verification_code missing");
            context.failure(AuthenticationFlowError.INVALID_USER, challengeResponse);
        } else if (StringUtils.isBlank(reference)) {

            Response challengeResponse = this.errorResponse(Response.Status.UNAUTHORIZED.getStatusCode(),
                    "reference missing");
            context.failure(AuthenticationFlowError.INVALID_USER, challengeResponse);
        } else {
            emailAuthenticatorProvider.authenticate(context);
            FlowStatus status = context.getStatus();
            logger.info("MultiFactorAuthenticator validateEmail " + status);
            return !Objects.equals(FlowStatus.FAILED, status);
        }
        return false;
    }

    private boolean validateOtp(AuthenticationFlowContext context) {
        ValidateOTP otpAuthenticator = new ValidateOTP();
        try {
            otpAuthenticator.authenticate(context);
            FlowStatus status = context.getStatus();
            logger.info("MultiFactorAuthenticator validateOtp " + status);
            return !Objects.equals(FlowStatus.FAILED, status);
        } catch (Exception e) {
            logger.error("MultiFactorAuthenticator validateOtp {0}", e);
            return false;
        }
    }

    private boolean validateWebAuthn(AuthenticationFlowContext context) {
        WebAuthn2MFAAuthenticator webAuthnAuthenticator = new WebAuthn2MFAAuthenticator();
        try {
            String credential = context.getHttpRequest()
                    .getDecodedFormParameters()
                    .getFirst("credential");
            String reference = context.getHttpRequest()
                    .getDecodedFormParameters()
                    .getFirst("reference");
            if (StringUtils.isBlank(credential)) {
                Response challengeResponse = this.errorResponse(Response.Status.UNAUTHORIZED.getStatusCode(),
                        "credential missing");
                context.failure(AuthenticationFlowError.INVALID_USER, challengeResponse);
                return false;
            } else if (StringUtils.isBlank(reference)) {

                Response challengeResponse = this.errorResponse(Response.Status.UNAUTHORIZED.getStatusCode(),
                        "reference missing");
                context.failure(AuthenticationFlowError.INVALID_USER, challengeResponse);
                return false;
            }
            webAuthnAuthenticator.authenticate(context);
            FlowStatus status = context.getStatus();
            logger.info("MultiFactorAuthenticator validateWebAuthn " + status);
            return !Objects.equals(FlowStatus.FAILED, status);
        } catch (Exception e) {
            logger.error("MultiFactorAuthenticator validateWebAuthn {0}", e);
            return false;
        }
    }

    @Override
    public void action(AuthenticationFlowContext context) {
        // Handle any additional actions if necessary
    }

    @Override
    public boolean requiresUser() {
        return true;
    }

    @Override
    public boolean configuredFor(org.keycloak.models.KeycloakSession session, org.keycloak.models.RealmModel realm, UserModel user) {
        return true;
    }

    @Override
    public void setRequiredActions(org.keycloak.models.KeycloakSession session, org.keycloak.models.RealmModel realm, UserModel user) {
        // No additional actions required
    }

    @Override
    public void close() {
        // Clean up resources if needed
    }


    private Response errorResponse(int statusCode, String invalidUserCredentials) {
        return Response.status(statusCode)
                .entity(new ErrorDto(invalidUserCredentials))
                .build();
    }




    public AuthenticatorConfigModel getAuthenticatorConfigByKey(KeycloakSession session, String providerId) {
        RealmModel realm = session.getContext().getRealm();
        List<AuthenticatorConfigModel> configs = realm.getAuthenticatorConfigsStream().toList();
        for (AuthenticatorConfigModel config : configs) {
            if (config.getConfig() != null && config.getConfig().containsKey(providerId)) {
                return config;
            }
        }
        return null; // Return null if no matching config is found
    }
}
