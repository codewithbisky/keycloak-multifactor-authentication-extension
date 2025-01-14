package com.codewithbisky.authentication.extension.rest;

import com.codewithbisky.authentication.extension.dto.EmailReferenceResponse;
import jakarta.ws.rs.*;
import jakarta.ws.rs.core.Response;
import org.jboss.logging.Logger;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.UserModel;
import org.keycloak.services.managers.AppAuthManager;
import org.keycloak.services.managers.AuthenticationManager;
import org.keycloak.utils.MediaType;
import com.codewithbisky.authentication.extension.MultiFactorAuthenticator;
import com.codewithbisky.authentication.extension.MultiFactorAuthenticatorFactory;
import com.codewithbisky.authentication.extension.email.EmailAuthenticatorDirectGrant;
import com.codewithbisky.authentication.extension.email.EmailConstants;
import com.codewithbisky.authentication.extension.email.EmailData;
import com.codewithbisky.authentication.extension.util.ProvidersUtil;

import java.sql.SQLException;

import static com.codewithbisky.authentication.extension.util.KeycloakSessionUtil.getUserSupportedMfa;
import static com.codewithbisky.authentication.extension.util.ProvidersUtil.getMultiFactorAuthenticatorProvider;

public class TwoFactorAuthRestResource {
    private static final Logger logger = Logger.getLogger(TwoFactorAuthRestResource.class);

    private final KeycloakSession session;
    private final AuthenticationManager.AuthResult auth;

    public TwoFactorAuthRestResource(KeycloakSession session) {
        this.session = session;
        this.auth = new AppAuthManager.BearerTokenAuthenticator(session).authenticate();
    }

    // Same like "companies" endpoint, but REST endpoint is authenticated with Bearer token and user must be in realm role "admin"
    // Just for illustration purposes
    @Path("manage-2fa/{user_id}")
    public User2FAResource getCompanyResource(@PathParam("user_id") final String userid) {
        final UserModel user = checkPermissionsAndGetUser(userid);
        return new User2FAResource(session, user);
    }

    private UserModel checkPermissionsAndGetUser(final String userid) {
        if (auth == null) {
            var auth = new AppAuthManager.BearerTokenAuthenticator(session);
            auth.authenticate();
            throw new NotAuthorizedException("Bearer");
        }
        final UserModel user = this.session.users().getUserById(this.session.getContext().getRealm(), userid);
        if (user == null) {
            throw new BadRequestException("invalid user");
        }

        return user;
    }

    @Path("webauth/{user_id}")
    public WebAuthRegistrationResource getWebAuthResource(@PathParam("user_id") final String userid) throws SQLException {
        final UserModel user = checkPermissionsAndGetUser(userid);
        return new WebAuthRegistrationResource(session, user);
    }

    @Path("webauth/login")
    public WebAuthLoginResource login() throws SQLException {
        return new WebAuthLoginResource(session);
    }


    @Path("methods")
    @GET
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response methods(@QueryParam("username") final String username) {
        final UserModel user = getUserByUsername(username);
        return Response.ok().entity(getUserSupportedMfa(user,session)).build();
    }





    private UserModel getUserByUsername(final String username) {

        final UserModel user = this.session.users().getUserByUsername(this.session.getContext().getRealm(), username);
        if (user == null) {
            throw new BadRequestException("user does not exist for username: " + username);
        }
        return user;
    }

    @POST
    @Path("send")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response sendEmail(@QueryParam("username") final String username,
                              @QueryParam("2nd_factor_type") final String type) {

        if (type == null || !type.equals("email")) {
            throw new BadRequestException("invalid 2nd factor type: " + type);
        }
        final UserModel user = getUserByUsername(username);
        return sendEmail(type, user);
    }

    private Response sendEmail(String type, UserModel user) {
        EmailAuthenticatorDirectGrant emailAuthenticatorProvider = ProvidersUtil.getEmailAuthenticatorProvider(session);
        MultiFactorAuthenticator authenticatorProvider = getMultiFactorAuthenticatorProvider(session);
        AuthenticatorConfigModel authenticatorConfig = authenticatorProvider
                .getAuthenticatorConfigByKey(session, MultiFactorAuthenticatorFactory.ENABLE_EMAIL_2ND_AUTHENTICATION);
        int length = EmailConstants.DEFAULT_LENGTH;
        int ttl = EmailConstants.DEFAULT_TTL;
        if (authenticatorConfig != null && authenticatorConfig.getConfig() != null
                && authenticatorConfig.getConfig().containsKey(EmailConstants.CODE_LENGTH) &&
                authenticatorConfig.getConfig().containsKey(EmailConstants.CODE_TTL)) {
            length = Integer.parseInt(authenticatorConfig.getConfig().get(EmailConstants.CODE_LENGTH));
            ttl = Integer.parseInt(authenticatorConfig.getConfig().get(EmailConstants.CODE_TTL));
        }
        EmailData emailData = emailAuthenticatorProvider.generateAndSendEmailCode(session, user, length, ttl);
        return Response.ok()
                .entity(new EmailReferenceResponse(emailData.reference(), type))
                .build();
    }


}
