package com.codewithbisky.authentication.extension.email.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.Getter;
import lombok.Setter;

@Entity
@Table(name = "two_factor_otp")
@Getter
@Setter
public class TwoFactorOtpEntity {

    @Id
    @Column(name = "id")
    private String id;

    @Column(name = "user_id", columnDefinition = "TEXT")
    private String userId;

    @Column(name = "type", columnDefinition = "TEXT")
    private String type;

    @Column(name = "status", columnDefinition = "TEXT")
    private String status;

    @Column(name = "code", columnDefinition = "TEXT")
    private String code;

    @Column(name = "ttl")
    private Long ttl;

}
