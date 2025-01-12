package org.prg.twofactorauth.dto;

import com.yubico.webauthn.AssertionRequest;

public class LoginStartResponse {
  private String reference;
  private AssertionRequest assertionRequest;

  public String getReference() {
    return reference;
  }

  public void setReference(String reference) {
    this.reference = reference;
  }

  public AssertionRequest getAssertionRequest() {
    return assertionRequest;
  }

  public void setAssertionRequest(AssertionRequest assertionRequest) {
    this.assertionRequest = assertionRequest;
  }
}
