package org.prg.twofactorauth.webauthn.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import org.prg.twofactorauth.util.JsonUtils;

@Entity
@Table(name = "webauthn_registration_flow")
public class RegistrationFlowEntity {

  @Id
  @Column(name = "id")
  private String id;

  @Column(name = "start_request",columnDefinition = "TEXT")
  private String startRequest;

  @Column(name = "start_response",columnDefinition = "TEXT")
  private String startResponse;

  @Column(name = "finish_request",columnDefinition = "TEXT")
  private String finishRequest;

  @Column(name = "finish_response",columnDefinition = "TEXT")
  private String finishResponse;

  @Column(name = "yubico_reg_result",columnDefinition = "TEXT")
  private String registrationResult;

  @Column(name = "yubico_creation_options",columnDefinition = "TEXT")
  private String creationOptions;

  public String getCreationOptions() {
    return creationOptions;
  }

  public void setCreationOptions(String creationOptions) {
    this.creationOptions = creationOptions;
  }

  public String getRegistrationResult() {
    return registrationResult;
  }

  public void setRegistrationResult(String registrationResult) {
    this.registrationResult = registrationResult;
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

  public String getFinishRequest() {
    return finishRequest;
  }

  public void setFinishRequest(String finishRequest) {
    this.finishRequest = finishRequest;
  }

  public String getFinishResponse() {
    return finishResponse;
  }

  public void setFinishResponse(String finishResponse) {
    this.finishResponse = finishResponse;
  }

  @Override
  public String toString() {
    return JsonUtils.toJson(this);
  }
}
