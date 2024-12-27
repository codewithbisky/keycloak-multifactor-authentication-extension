package org.prg.twofactorauth.rest;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.yubico.webauthn.RelyingParty;
import com.yubico.webauthn.StartRegistrationOptions;
import com.yubico.webauthn.data.AuthenticatorSelectionCriteria;
import com.yubico.webauthn.data.PublicKeyCredentialCreationOptions;
import com.yubico.webauthn.data.UserIdentity;
import com.yubico.webauthn.data.UserVerificationRequirement;
import com.yubico.webauthn.exception.AssertionFailedException;
import com.yubico.webauthn.exception.RegistrationFailedException;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.Response;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.UserModel;
import org.keycloak.utils.MediaType;
import org.prg.twofactorauth.dto.*;
import org.prg.twofactorauth.webauthn.domain.*;
import org.prg.twofactorauth.webauthn.entity.RegistrationFlowEntity;
import org.prg.twofactorauth.webauthn.model.UserAccount;

import java.io.IOException;
import java.sql.SQLException;
import java.util.Map;
import java.util.UUID;

import static org.prg.twofactorauth.util.JsonUtils.toJson;

public class WebAuthLoginResource {

    private final KeycloakSession session;
    RelyingParty relyingParty;
    UserService userService;

    public WebAuthLoginResource(KeycloakSession session) throws SQLException {
        this.session = session;
        userService = new UserServiceImpl(session, null, DbUtil.getEntityManager(session));
        relyingParty = RelyingPartyConfiguration.relyingParty(userService);
    }

    @POST
    @Path("start")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response loginStart(final LoginStartRequest request) throws JsonProcessingException {

        return Response.accepted().entity(userService.startLogin(request)).build();
    }

    @POST
    @Path("finish")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response loginFinish(final LoginFinishRequest request) throws  IOException, AssertionFailedException {

        Map<String, Object> result = this.userService.finishLogin(request);
        return Response.accepted().entity(result).build();
    }


}
