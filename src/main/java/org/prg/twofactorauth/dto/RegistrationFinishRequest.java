package org.prg.twofactorauth.dto;

import com.yubico.webauthn.data.AuthenticatorAttestationResponse;
import com.yubico.webauthn.data.ClientRegistrationExtensionOutputs;
import com.yubico.webauthn.data.PublicKeyCredential;

public class RegistrationFinishRequest {

  private String flowId;
  private PublicKeyCredential<AuthenticatorAttestationResponse, ClientRegistrationExtensionOutputs>
      credential;
  private RegistrationStartResponse startRequest;

  public String getFlowId() {
    return flowId;
  }

  public void setFlowId(String flowId) {
    this.flowId = flowId;
  }

  public PublicKeyCredential<AuthenticatorAttestationResponse, ClientRegistrationExtensionOutputs>
      getCredential() {
    return credential;
  }

  public void setCredential(
      PublicKeyCredential<AuthenticatorAttestationResponse, ClientRegistrationExtensionOutputs>
          credential) {
    this.credential = credential;
  }

  public RegistrationStartResponse getStartRequest() {
    return startRequest;
  }

  public void setStartRequest(RegistrationStartResponse startRequest) {
    this.startRequest = startRequest;
  }
}
