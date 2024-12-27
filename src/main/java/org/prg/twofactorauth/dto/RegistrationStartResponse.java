package org.prg.twofactorauth.dto;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonInclude.Include;
import com.yubico.webauthn.data.PublicKeyCredentialCreationOptions;

import java.util.UUID;

@JsonInclude(Include.NON_NULL)
public class RegistrationStartResponse {
  private String flowId;
  private PublicKeyCredentialCreationOptions credentialCreationOptions;

  public String getFlowId() {
    return flowId;
  }

  public void setFlowId(String flowId) {
    this.flowId = flowId;
  }

  public PublicKeyCredentialCreationOptions getCredentialCreationOptions() {
    return credentialCreationOptions;
  }

  public void setCredentialCreationOptions(
      PublicKeyCredentialCreationOptions credentialCreationOptions) {
    this.credentialCreationOptions = credentialCreationOptions;
  }
}
