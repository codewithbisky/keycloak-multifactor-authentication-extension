package org.prg.twofactorauth.dto;

public class RegistrationFinishResponse {
  private String reference;
  private boolean registrationComplete;

  public String getReference() {
    return reference;
  }

  public void setReference(String reference) {
    this.reference = reference;
  }

  public boolean isRegistrationComplete() {
    return registrationComplete;
  }

  public void setRegistrationComplete(boolean registrationComplete) {
    this.registrationComplete = registrationComplete;
  }
}
