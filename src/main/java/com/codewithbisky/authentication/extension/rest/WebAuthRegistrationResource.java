package com.codewithbisky.authentication.extension.rest;

import com.codewithbisky.authentication.extension.dto.RegistrationFinishRequest;
import com.codewithbisky.authentication.extension.dto.RegistrationFinishResponse;
import com.codewithbisky.authentication.extension.dto.RegistrationStartRequest;
import com.codewithbisky.authentication.extension.util.JsonUtils;
import com.codewithbisky.authentication.extension.webauthn.domain.*;
import com.codewithbisky.authentication.extension.webauthn.model.UserAccount;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.yubico.webauthn.RelyingParty;
import com.yubico.webauthn.StartRegistrationOptions;
import com.yubico.webauthn.data.AuthenticatorSelectionCriteria;
import com.yubico.webauthn.data.PublicKeyCredentialCreationOptions;
import com.yubico.webauthn.data.UserIdentity;
import com.yubico.webauthn.data.UserVerificationRequirement;
import com.yubico.webauthn.exception.RegistrationFailedException;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.Response;
import org.jboss.logging.Logger;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.UserModel;
import org.keycloak.utils.MediaType;
import com.codewithbisky.authentication.extension.dto.RegistrationStartResponse;
import com.codewithbisky.authentication.extension.webauthn.entity.RegistrationFlowEntity;

import java.io.IOException;
import java.sql.SQLException;
import java.util.*;

public class WebAuthRegistrationResource {
    private static final Logger logger = Logger.getLogger(WebAuthRegistrationResource.class);

    private final KeycloakSession session;
    private final UserModel user;
    RelyingParty relyingParty;
    UserService userService;

    public WebAuthRegistrationResource(KeycloakSession session, UserModel user) throws SQLException {
        this.session = session;
        this.user = user;
        userService = new UserServiceImpl(session, user, DbUtil.getEntityManager(session));
    }

    @POST
    @Path("register/start")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response registerStart(final RegistrationStartRequest startRequest) throws JsonProcessingException {

        UserAccount user =
                this.userService.createOrFindUser(startRequest.getFullName(), startRequest.getEmail());
        PublicKeyCredentialCreationOptions options = createPublicKeyCredentialCreationOptions(user);
        RegistrationStartResponse startResponse = createRegistrationStartResponse(options);
        logWorkflow(startRequest, startResponse);


        return Response.accepted().entity(startResponse).build();
    }

    @POST
    @Path("register/finish")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response registerFinish(final RegistrationFinishRequest request) throws RegistrationFailedException, IOException {


        RegistrationFinishResponse result = this.userService.finishRegistration(request);
        return Response.accepted().entity(result).build();
    }


    private RegistrationStartResponse createRegistrationStartResponse(
            PublicKeyCredentialCreationOptions options) {
        RegistrationStartResponse startResponse = new RegistrationStartResponse();
        startResponse.setReference(UUID.randomUUID().toString());
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

        relyingParty = RelyingPartyConfiguration.relyingParty(userService, user);
        return this.relyingParty.startRegistration(startRegistrationOptions);
    }


    private void logWorkflow(
            RegistrationStartRequest startRequest, RegistrationStartResponse startResponse) throws JsonProcessingException {
        RegistrationFlowEntity registrationEntity = new RegistrationFlowEntity();
        registrationEntity.setId(startResponse.getReference());
        registrationEntity.setStartRequest(JsonUtils.toJson(startRequest));
        registrationEntity.setStartResponse(JsonUtils.toJson(startResponse));
        registrationEntity.setRegistrationResult(startResponse.getCredentialCreationOptions().toJson());
        userService.insertRegistrationFlow(registrationEntity);
    }



}
