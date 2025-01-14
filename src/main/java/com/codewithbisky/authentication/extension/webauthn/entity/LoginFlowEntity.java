package com.codewithbisky.authentication.extension.webauthn.entity;

import com.codewithbisky.authentication.extension.util.JsonUtils;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

@Entity
@Table(name = "webauthn_login_flow")
public class LoginFlowEntity {

  @Id
  @Column(name = "id")
  private String id;

  @Column(name = "start_request",columnDefinition = "TEXT")
  private String startRequest;

  @Column(name = "start_response",columnDefinition = "TEXT")
  private String startResponse;

  @Column(name = "successful_login")
  private Boolean successfulLogin;

  @Column(name = "assertion_request",columnDefinition = "TEXT")
  private String assertionRequest;

  @Column(name = "assertion_result",columnDefinition = "TEXT")
  private String assertionResult;

  @Column(name = "user_name",columnDefinition = "TEXT")
  private String username;


  @Override
  public String toString() {
    return JsonUtils.toJson(this);
  }

  public String getId() {
    return id;
  }

  public void setId(String id) {
    this.id = id;
  }

  public String getStartRequest() {
    return startRequest;
  }

  public void setStartRequest(String startRequest) {
    this.startRequest = startRequest;
  }

  public String getStartResponse() {
    return startResponse;
  }

  public void setStartResponse(String startResponse) {
    this.startResponse = startResponse;
  }

  public Boolean getSuccessfulLogin() {
    return successfulLogin;
  }

  public void setSuccessfulLogin(Boolean successfulLogin) {
    this.successfulLogin = successfulLogin;
  }

  public String getAssertionRequest() {
    return assertionRequest;
  }

  public void setAssertionRequest(String assertionRequest) {
    this.assertionRequest = assertionRequest;
  }

  public String getAssertionResult() {
    return assertionResult;
  }

  public void setAssertionResult(String assertionResult) {
    this.assertionResult = assertionResult;
  }

  public String getUsername() {
    return username;
  }

  public void setUsername(String username) {
    this.username = username;
  }
}
