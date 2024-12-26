package org.prg.twofactorauth.rest;

import com.google.gson.Gson;
import jakarta.ws.rs.*;
import jakarta.ws.rs.core.Response;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.UserModel;
import org.keycloak.utils.MediaType;
import org.prg.twofactorauth.dto.RegistrationStartRequest;

public class WebAuthRegistrationResource {

	private final KeycloakSession session;
    private final UserModel user;

	public WebAuthRegistrationResource(KeycloakSession session, UserModel user) {
		this.session = session;
        this.user = user;
	}

    @POST
    @Path("register/start")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response register2FA(final RegistrationStartRequest registrationStartRequest) {

        Gson gson=new Gson();
        System.out.println(gson.toJson(registrationStartRequest));
        return Response.accepted().entity(registrationStartRequest).build();
    }

}
