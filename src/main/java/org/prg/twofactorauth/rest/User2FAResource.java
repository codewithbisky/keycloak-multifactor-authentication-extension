package org.prg.twofactorauth.rest;

import jakarta.ws.rs.*;
import jakarta.ws.rs.core.Response;
import org.keycloak.credential.CredentialModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.credential.OTPCredentialModel;
import org.keycloak.models.utils.Base32;
import org.keycloak.models.utils.HmacOTP;
import org.keycloak.utils.CredentialHelper;
import org.keycloak.utils.MediaType;
import org.keycloak.utils.TotpUtils;
import org.prg.twofactorauth.dto.TwoFactorAuthSecretData;
import org.prg.twofactorauth.dto.TwoFactorAuthSubmission;

public class User2FAResource {

	private final KeycloakSession session;
    private final UserModel user;

    public final int TotpSecretLength = 20;
	
	public User2FAResource(KeycloakSession session, UserModel user) {
		this.session = session;
        this.user = user;
	}

    @GET
    @Path("generate-2fa")
    @Produces(MediaType.APPLICATION_JSON)
    @Consumes(MediaType.APPLICATION_JSON)
    public Response generate2FA() {
        final RealmModel realm = this.session.getContext().getRealm();
        final String totpSecret = HmacOTP.generateSecret(TotpSecretLength);
        final String totpSecretQrCode = TotpUtils.qrCode(totpSecret, realm, user);
        final String totpSecretEncoded = Base32.encode(totpSecret.getBytes());
        return Response.ok(new TwoFactorAuthSecretData(totpSecretEncoded, totpSecretQrCode)).build();
    }



    @POST
    @Path("submit-2fa")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response register2FA(final TwoFactorAuthSubmission submission) {
        if (!submission.isValid()) {
            throw new BadRequestException("one or more data field for otp registration are blank");
        }

        final String encodedTotpSecret = submission.getEncodedTotpSecret();
        final String totpSecret = new String(Base32.decode(encodedTotpSecret));
        if (totpSecret.length() < TotpSecretLength) {
            throw new BadRequestException("totp secret is invalid");
        }

        final RealmModel realm = this.session.getContext().getRealm();
        final CredentialModel credentialModel = user.credentialManager().getStoredCredentialByNameAndType(submission.getDeviceName(), OTPCredentialModel.TYPE);
        if (credentialModel != null && !submission.isOverwrite()) {
            throw new ForbiddenException("2FA is already configured for device: " + submission.getDeviceName());
        }

        final OTPCredentialModel otpCredentialModel = OTPCredentialModel.createFromPolicy(realm, totpSecret, submission.getDeviceName());
        if (!CredentialHelper.createOTPCredential(this.session, realm, user, submission.getTotpInitialCode(), otpCredentialModel)) {
            throw new BadRequestException("otp registration data is invalid");
        }

        return Response.noContent().build();
    }

}
