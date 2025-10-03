export interface StartLoginResponse {
  reference: string
  assertionRequest: AssertionRequest
}

export interface AssertionRequest {
  publicKeyCredentialRequestOptions: PublicKeyCredentialRequestOptions
  username: string
  userHandle: any
}

export interface PublicKeyCredentialRequestOptions {
  challenge: string
  timeout: number
  rpId: string
  allowCredentials: AllowCredential[]
  userVerification: any
  extensions: Extensions
}

export interface AllowCredential {
  type: string
  id: string
  transports: any
}

export interface Extensions {
  appid: any
  largeBlob: any
  uvm: any
}
