package com.codewithbisky.authentication.extension.exception;

public class MissingConfigException extends RuntimeException{
    public MissingConfigException(String message) {
        super(message);
    }
}
