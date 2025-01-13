package org.prg.twofactorauth.webauthn;

import jakarta.ws.rs.core.Response;
import org.apache.commons.lang3.StringUtils;
import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.CredentialValidator;
import org.keycloak.credential.CredentialProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.prg.twofactorauth.dto.ErrorDto;
import org.prg.twofactorauth.dto.LoginFinishRequest;
import org.prg.twofactorauth.webauthn.credential.WebauthnCredentialProvider;
import org.prg.twofactorauth.webauthn.credential.WebauthnCredentialProviderFactory;
import org.prg.twofactorauth.webauthn.domain.DbUtil;
import org.prg.twofactorauth.webauthn.domain.UserService;
import org.prg.twofactorauth.webauthn.domain.UserServiceImpl;
import org.prg.twofactorauth.webauthn.entity.FidoCredentialEntity;

import java.util.List;
import java.util.Map;

import static org.prg.twofactorauth.util.JsonUtils.sanitizedJson;


public class WebAuthn2MFAAuthenticator implements Authenticator, CredentialValidator<WebauthnCredentialProvider> {

    private static final Logger logger = Logger.getLogger(WebAuthn2MFAAuthenticator.class);

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        action(context);
    }

    @Override
    public void action(AuthenticationFlowContext context) {

        if (!this.configuredFor(context.getSession(), context.getRealm(), context.getUser())) {
            if (context.getExecution().isConditional()) {
                context.attempted();
            } else if (context.getExecution().isRequired()) {
                context.getEvent().error("webauth_authentication_required");
                Response challengeResponse = this.errorResponse(Response.Status.UNAUTHORIZED.getStatusCode(),
                        "webauthn authentication required");
                context.failure(AuthenticationFlowError.INVALID_USER, challengeResponse);
            }
            return;
        }
        AuthenticationSessionModel session = context.getAuthenticationSession();
        String username = session.getAuthenticatedUser().getUsername();
        String credential = context.getHttpRequest()
                .getDecodedFormParameters()
                .getFirst("credential");
        String reference = context.getHttpRequest()
                .getDecodedFormParameters()
                .getFirst("reference");

        if(StringUtils.isBlank(credential)){

            if (context.getUser() != null) {
                context.getEvent().user(context.getUser());
            }
            context.getEvent().error("webauth_authentication_required");
            Response challengeResponse = this.errorResponse(Response.Status.UNAUTHORIZED.getStatusCode(),"Webauthn Credential missing");
            context.failure(AuthenticationFlowError.INVALID_USER, challengeResponse);
            return;
        }
        credential = sanitizedJson(credential);
        if (completeAuthentication(username, credential, reference, context)) {
            context.success();
        } else {
            Response errorResponse = Response.status(Response.Status.UNAUTHORIZED)
                    .entity(new ErrorDto("WebAuthn authentication failed"))
                    .build();
            context.failure(AuthenticationFlowError.INVALID_CREDENTIALS, errorResponse);
        }
    }

    private Response errorResponse(int statusCode, String invalidUserCredentials) {
  return Response.status(statusCode)
                .entity(new ErrorDto(invalidUserCredentials))
                .build();
    }

    private boolean completeAuthentication(String username,
                                           String credential,
                                           String reference,
                                           AuthenticationFlowContext context) {
        // Implement WebAuthn assertion validation logic
        // Use a WebAuthn library (e.g., Yubico's webauthn-server)
        try {
            logger.info("WebAuthn2MFAAuthenticator completeAuthentication validation ");

            KeycloakSession session = context.getSession();
            UserModel user = KeycloakModelUtils.findUserByNameOrEmail(session, context.getRealm(), username);
            UserService userService = new UserServiceImpl(session, user, DbUtil.getEntityManager(session));
            List<FidoCredentialEntity> credentialEntities = userService.findCredentialsByUserId(user.getId());
            if (credentialEntities.isEmpty()) {
                //no webauthn configured for the user and we can return success
                return true;
            }
            // webauthn configured and validation is required
            if (credential == null) {
                return false;
            }
            LoginFinishRequest request = new LoginFinishRequest();
            request.setReference(reference);
            request.setCredential(credential);
            Map<String, Object> map = userService.finishLogin(request,user.getUsername());
            return map.containsKey("success");
        } catch (Exception e) {
            logger.error("WebAuthn2MFAAuthenticator completeAuthentication " + e);
            return false;
        }
    }

    @Override
    public boolean requiresUser() {
        return true;
    }

    @Override
    public boolean configuredFor(KeycloakSession keycloakSession,
                                 RealmModel realmModel, UserModel userModel) {

        return getCredentialProvider(keycloakSession).isConfiguredFor(realmModel, userModel, getType(keycloakSession));
    }

    @Override
    public void setRequiredActions(KeycloakSession keycloakSession,
                                   RealmModel realmModel, UserModel userModel) {

    }


    @Override
    public void close() {
    }

    @Override
    public WebauthnCredentialProvider getCredentialProvider(KeycloakSession keycloakSession) {
        return (WebauthnCredentialProvider) keycloakSession.getProvider(CredentialProvider.class, WebauthnCredentialProviderFactory.PROVIDER_ID);

    }
}
