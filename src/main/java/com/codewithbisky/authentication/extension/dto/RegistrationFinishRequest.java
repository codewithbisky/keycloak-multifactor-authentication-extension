package com.codewithbisky.authentication.extension.dto;

public class RegistrationFinishRequest {

    private String reference;
    private String credential;

    public String getReference() {
        return reference;
    }

    public void setReference(String reference) {
        this.reference = reference;
    }

    public String getCredential() {
        return credential;
    }

    public void setCredential(String credential) {
        this.credential = credential;
    }


}
