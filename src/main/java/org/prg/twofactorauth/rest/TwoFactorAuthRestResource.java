package org.prg.twofactorauth.rest;

import jakarta.ws.rs.*;
import jakarta.ws.rs.core.Response;
import org.keycloak.credential.CredentialProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.UserModel;
import org.keycloak.services.managers.AppAuthManager;
import org.keycloak.services.managers.AuthenticationManager;
import org.keycloak.utils.MediaType;
import org.prg.twofactorauth.webauthn.credential.WebAuthnCredentialModel;
import org.prg.twofactorauth.webauthn.credential.WebauthnCredentialProvider;
import org.prg.twofactorauth.webauthn.credential.WebauthnCredentialProviderFactory;

import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;

public class TwoFactorAuthRestResource {

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
        } else if (auth.getToken().getRealmAccess() == null || !auth.getToken().getRealmAccess().isUserInRole("manage-2fa")) {
            throw new ForbiddenException("Does not have realm manage-2fa role");
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
        List<String> credentials = new ArrayList<>();
        boolean webAuthnConfigured = webAuthnConfigured(user);
        if (webAuthnConfigured) {
            credentials.add("webauthn");
        }
        boolean otp = user.credentialManager().getStoredCredentialsByTypeStream("otp").findAny().isPresent();
        if (otp) {
            credentials.add("otp");
        }
        return Response.ok().entity(credentials).build();
    }

    public boolean webAuthnConfigured(UserModel user) {
        return getCredentialProvider(session).isConfiguredFor(session.getContext().getRealm(), user, WebAuthnCredentialModel.TYPE);
    }

    public WebauthnCredentialProvider getCredentialProvider(KeycloakSession keycloakSession) {
        return (WebauthnCredentialProvider) keycloakSession.getProvider(CredentialProvider.class, WebauthnCredentialProviderFactory.PROVIDER_ID);

    }


    private UserModel getUserByUsername(final String username) {

        final UserModel user = this.session.users().getUserByUsername(this.session.getContext().getRealm(), username);
        if (user == null) {
            throw new BadRequestException("user does not exist for username: " + username);
        }
        return user;
    }

}
