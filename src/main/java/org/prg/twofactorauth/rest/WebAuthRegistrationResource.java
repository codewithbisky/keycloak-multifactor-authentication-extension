package org.prg.twofactorauth.rest;

import com.google.gson.Gson;
import com.yubico.webauthn.RelyingParty;
import com.yubico.webauthn.StartRegistrationOptions;
import com.yubico.webauthn.data.AuthenticatorSelectionCriteria;
import com.yubico.webauthn.data.PublicKeyCredentialCreationOptions;
import com.yubico.webauthn.data.UserIdentity;
import com.yubico.webauthn.data.UserVerificationRequirement;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.Response;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.UserModel;
import org.keycloak.utils.MediaType;
import org.prg.twofactorauth.dto.RegistrationStartRequest;
import org.prg.twofactorauth.dto.RegistrationStartResponse;
import org.prg.twofactorauth.webauthn.domain.RelyingPartyConfiguration;
import org.prg.twofactorauth.webauthn.domain.UserService;
import org.prg.twofactorauth.webauthn.domain.UserServiceImpl;
import org.prg.twofactorauth.webauthn.domain.YubicoUtils;
import org.prg.twofactorauth.webauthn.model.UserAccount;

import java.util.UUID;

public class WebAuthRegistrationResource {

    private final KeycloakSession session;
    private final UserModel user;
    RelyingParty relyingParty = RelyingPartyConfiguration.relyingParty();
    UserService userService;

    public WebAuthRegistrationResource(KeycloakSession session, UserModel user) {
        this.session = session;
        this.user = user;
        userService =new UserServiceImpl(session,user);
    }

    @POST
    @Path("register/start")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response register2FA(final RegistrationStartRequest startRequest) {

        UserAccount user =
                this.userService.createOrFindUser(startRequest.getFullName(), startRequest.getEmail());
        PublicKeyCredentialCreationOptions options = createPublicKeyCredentialCreationOptions(user);
        RegistrationStartResponse startResponse = createRegistrationStartResponse(options);

        //todo logWorkflow(startRequest, startResponse);

        return Response.accepted().entity(startResponse).build();
    }


    private RegistrationStartResponse createRegistrationStartResponse(
            PublicKeyCredentialCreationOptions options) {
        RegistrationStartResponse startResponse = new RegistrationStartResponse();
        startResponse.setFlowId(UUID.randomUUID());
        startResponse.setCredentialCreationOptions(options);
        return startResponse;
    }

    private PublicKeyCredentialCreationOptions createPublicKeyCredentialCreationOptions(
            UserAccount user) {
        var userIdentity =
                UserIdentity.builder()
                        .name(user.getEmail())
                        .displayName(user.getDisplayName())
                        .id(YubicoUtils.toByteArray(UUID.fromString(user.getId())))
                        .build();

        var authenticatorSelectionCriteria =
                AuthenticatorSelectionCriteria.builder()
                        .userVerification(UserVerificationRequirement.DISCOURAGED)
                        .build();

        var startRegistrationOptions =
                StartRegistrationOptions.builder()
                        .user(userIdentity)
                        .timeout(30_000)
                        .authenticatorSelection(authenticatorSelectionCriteria)
                        .build();


        PublicKeyCredentialCreationOptions options =
                this.relyingParty.startRegistration(startRegistrationOptions);

        return options;
    }

}
