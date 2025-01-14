package com.codewithbisky.authentication.extension.dto;

public class RegistrationStartRequest {
  private String fullName;
  private String username;

  public String getFullName() {
    return fullName;
  }

  public void setFullName(String fullName) {
    this.fullName = fullName;
  }

  public String getUsername() {
    return username;
  }

  public void setUsername(String username) {
    this.username = username;
  }

  @Override
  public String toString() {
    return "RegistrationStartRequest[" + "fullName=" + fullName + ", " + "email=" + username + ']';
  }
}
