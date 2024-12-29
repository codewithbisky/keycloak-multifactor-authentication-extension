package org.prg.twofactorauth.rest;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.yubico.webauthn.RelyingParty;
import com.yubico.webauthn.exception.AssertionFailedException;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.Response;
import org.keycloak.models.KeycloakSession;
import org.keycloak.utils.MediaType;
import org.prg.twofactorauth.dto.LoginFinishRequest;
import org.prg.twofactorauth.dto.LoginStartRequest;
import org.prg.twofactorauth.webauthn.domain.DbUtil;
import org.prg.twofactorauth.webauthn.domain.UserService;
import org.prg.twofactorauth.webauthn.domain.UserServiceImpl;

import java.io.IOException;
import java.sql.SQLException;
import java.util.Map;

public class WebAuthLoginResource {

    private final KeycloakSession session;
    UserService userService;

    public WebAuthLoginResource(KeycloakSession session) throws SQLException {
        this.session = session;
        userService = new UserServiceImpl(session, null, DbUtil.getEntityManager(session));
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
