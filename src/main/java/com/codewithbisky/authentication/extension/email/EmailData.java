package com.codewithbisky.authentication.extension.email;

public record EmailData(String reference, String code,Long ttl,String userId) {
}
