export interface StartResponse {
  reference: string
  jsonResponse: string
  credentialCreationOptions: CredentialCreationOptions
}

export interface CredentialCreationOptions {
  rp: Rp
  user: User
  challenge: string
  pubKeyCredParams: PublicKeyCredentialParameters[]
  timeout: number
  excludeCredentials: any[]
  authenticatorSelection: AuthenticatorSelection
  attestation: AttestationConveyancePreference
  extensions: Extensions
}

export interface Rp {
  name: string
  id: string
}

export interface User {
  name: string
  displayName: string
  id: string
}

export interface PubKeyCredParam {
  alg: number
  type: string
}

export interface AuthenticatorSelection {
  authenticatorAttachment: any
  requireResidentKey: any
  residentKey: any
  userVerification: string
}

export interface Extensions {
  appidExclude: any
  credProps: boolean
  largeBlob: any
  uvm: any
}
