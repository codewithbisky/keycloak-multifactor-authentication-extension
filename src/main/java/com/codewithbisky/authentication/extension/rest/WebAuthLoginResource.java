package com.codewithbisky.authentication.extension.rest;

import com.codewithbisky.authentication.extension.webauthn.domain.DbUtil;
import com.codewithbisky.authentication.extension.webauthn.domain.UserService;
import com.codewithbisky.authentication.extension.webauthn.domain.UserServiceImpl;
import com.fasterxml.jackson.core.JsonProcessingException;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.Response;
import org.keycloak.models.KeycloakSession;
import org.keycloak.utils.MediaType;
import com.codewithbisky.authentication.extension.dto.LoginStartRequest;

import java.sql.SQLException;

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

        return Response.ok().entity(userService.startLogin(request)).build();
    }


}
