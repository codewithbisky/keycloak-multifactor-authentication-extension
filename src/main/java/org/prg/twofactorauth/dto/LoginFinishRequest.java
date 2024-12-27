package org.prg.twofactorauth.dto;

public class LoginFinishRequest {
    private String flowId;
    private String credential;

    public String getFlowId() {
        return flowId;
    }

    public void setFlowId(String flowId) {
        this.flowId = flowId;
    }

    public String getCredential() {
        return credential;
    }

    public void setCredential(String credential) {
        this.credential = credential;
    }
}
