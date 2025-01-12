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

import java.util.Objects;

import static org.prg.twofactorauth.MultiFactorAuthenticatorFactory.ENABLE_EMAIL_2ND_AUTHENTICATION;

public class MultiFactorAuthenticator implements Authenticator {

    private static final Logger logger = Logger.getLogger(MultiFactorAuthenticator.class);

    @Override
    public void authenticate(AuthenticationFlowContext context) {

        UserModel user = context.getUser();
        boolean isOtpConfigured =
                ((OTPCredentialProvider) getCredentialProvider(
                        context.getSession(), "keycloak-otp"))
                        .isConfiguredFor(context.getRealm(), user, "otp");
        boolean isWebAuthnConfigured = ((WebauthnCredentialProvider) getCredentialProvider(
                context.getSession(), WebauthnCredentialProviderFactory.PROVIDER_ID))
                .isConfiguredFor(context.getRealm(), user,
                        WebAuthnCredentialModel.TYPE);

        boolean otpValidationSuccess = false;
        boolean webAuthnValidationSuccess = false;

        if (isOtpConfigured) {
            otpValidationSuccess = validateOtp(context);
        }

        if (!otpValidationSuccess && isWebAuthnConfigured) {
            webAuthnValidationSuccess = validateWebAuthn(context);
        }

        AuthenticatorConfigModel config = context.getAuthenticatorConfig();
        boolean allowEmailAuthentication = config != null && Boolean.parseBoolean(config.getConfig().get(ENABLE_EMAIL_2ND_AUTHENTICATION));
        logger.info("Allow Email Authentication "+allowEmailAuthentication);
        if (otpValidationSuccess || webAuthnValidationSuccess) {
            context.success();
        } else if (isOtpConfigured || isWebAuthnConfigured) {
            Response challengeResponse = this.errorResponse(Response.Status.UNAUTHORIZED.getStatusCode(),
                    "2nd authentication is required");
            context.failure(AuthenticationFlowError.INVALID_USER, challengeResponse);
        } else if (allowEmailAuthentication) {
            boolean validateEmail = validateEmail(context);
            if (validateEmail) {
                context.success();
            }
        } else {
            context.success();
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
        if (StringUtils.isBlank(verificationCode) || StringUtils.isBlank(reference)) {

            EmailData emailData = emailAuthenticatorProvider.generateAndSendEmailCode(context);
            emailAuthenticatorProvider.authenticate(context);
            Response challengeResponse = this.emailRerenceResponse(Response.Status.BAD_REQUEST.getStatusCode(),
                    emailData.reference());
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


    public CredentialProvider getCredentialProvider(KeycloakSession keycloakSession, String providerId) {
        return keycloakSession.getProvider(CredentialProvider.class, providerId);
    }

    private Response errorResponse(int statusCode, String invalidUserCredentials) {
        return Response.status(statusCode)
                .entity(new ErrorDto(invalidUserCredentials))
                .build();
    }

    private Response emailRerenceResponse(int statusCode, String reference) {
        return Response.status(statusCode)
                .entity(new EmailReferenceResponse(reference))
                .build();
    }


    public EmailAuthenticatorDirectGrant getEmailAuthenticatorProvider(KeycloakSession keycloakSession) {
        return (EmailAuthenticatorDirectGrant) keycloakSession.getProvider(Authenticator.class, EmailAuthenticatorDirectGrantFactory.PROVIDER_ID);
    }
}
