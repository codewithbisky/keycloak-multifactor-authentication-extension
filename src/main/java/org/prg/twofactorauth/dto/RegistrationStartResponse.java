package org.prg.twofactorauth.dto;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonInclude.Include;
import com.yubico.webauthn.data.PublicKeyCredentialCreationOptions;

@JsonInclude(Include.NON_NULL)
public class RegistrationStartResponse {
  private String reference;
  private String jsonResponse;
  private PublicKeyCredentialCreationOptions credentialCreationOptions;

  public String getReference() {
    return reference;
  }

  public void setReference(String reference) {
    this.reference = reference;
  }

  public PublicKeyCredentialCreationOptions getCredentialCreationOptions() {
    return credentialCreationOptions;
  }

  public void setCredentialCreationOptions(
      PublicKeyCredentialCreationOptions credentialCreationOptions) {
    this.credentialCreationOptions = credentialCreationOptions;
  }

  public String getJsonResponse() {
    return jsonResponse;
  }

  public void setJsonResponse(String jsonResponse) {
    this.jsonResponse = jsonResponse;
  }
}
