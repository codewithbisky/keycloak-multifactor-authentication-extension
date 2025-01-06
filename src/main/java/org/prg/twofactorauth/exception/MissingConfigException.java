package org.prg.twofactorauth.exception;

public class MissingConfigException extends RuntimeException{
    public MissingConfigException(String message) {
        super(message);
    }
}
