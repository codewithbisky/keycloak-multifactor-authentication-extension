package org.prg.twofactorauth.dto;

import com.yubico.webauthn.AssertionRequest;

import java.util.UUID;

public class LoginStartResponse {
  private String flowId;
  private AssertionRequest assertionRequest;

  public String getFlowId() {
    return flowId;
  }

  public void setFlowId(String flowId) {
    this.flowId = flowId;
  }

  public AssertionRequest getAssertionRequest() {
    return assertionRequest;
  }

  public void setAssertionRequest(AssertionRequest assertionRequest) {
    this.assertionRequest = assertionRequest;
  }
}
