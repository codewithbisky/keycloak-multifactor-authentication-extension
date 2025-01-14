package com.codewithbisky.authentication.extension.dto;

public class ErrorDto {
    private String error;

    public ErrorDto(String error) {
        this.error = error;
    }

    public String getError() {
        return error;
    }
}
