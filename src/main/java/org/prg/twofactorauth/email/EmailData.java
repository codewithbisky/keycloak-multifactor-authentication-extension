package org.prg.twofactorauth.email;

public record EmailData(String reference, String code,Long ttl,String userId) {
}
