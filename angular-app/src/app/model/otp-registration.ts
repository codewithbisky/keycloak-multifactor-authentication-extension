export interface OtpSecretData {
  encodedTotpSecret: string;
  totpSecretQRCode: string;
}

export interface OtpSubmission {
  device_name: string;
  encoded_totp_secret: string;
  totp_initial_code: string;
  should_overwrite?: boolean;
}

