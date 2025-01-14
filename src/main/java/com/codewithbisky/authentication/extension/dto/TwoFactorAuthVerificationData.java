package com.codewithbisky.authentication.extension.dto;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;

public class TwoFactorAuthVerificationData {
    private final String deviceName;
    private final String totpCode;
    private final String password;

    @JsonCreator
    public TwoFactorAuthVerificationData(@JsonProperty(value = "device_name") String deviceName, @JsonProperty(value = "totp_initial_code") String totpInitialCode, @JsonProperty(value = "password") String password) {
        this.deviceName = deviceName;
        this.totpCode = totpInitialCode;
        this.password = password;
    }

    public String getDeviceName() {
        return deviceName;
    }

    public String getTotpCode() {
        return totpCode;
    }

    public String getPassword() {
        return password;
    }

    public boolean isValid() {
        return deviceName != null &&
                totpCode != null &&
                password != null &&
                !deviceName.isBlank() &&
                !totpCode.isBlank() &&
                !password.isBlank();
    }
}
