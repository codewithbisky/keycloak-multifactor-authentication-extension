package org.prg.twofactorauth.dto;

public class RegistrationFinishResponse {
  private String flowId;
  private boolean registrationComplete;

  public String getFlowId() {
    return flowId;
  }

  public void setFlowId(String flowId) {
    this.flowId = flowId;
  }

  public boolean isRegistrationComplete() {
    return registrationComplete;
  }

  public void setRegistrationComplete(boolean registrationComplete) {
    this.registrationComplete = registrationComplete;
  }
}
