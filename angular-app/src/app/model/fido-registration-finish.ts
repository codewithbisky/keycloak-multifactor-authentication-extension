export interface FinishRequest {
  flowId: string
  credential: Credential
}

export interface Credential {
  id: string
  rawId: string
  type: string
  response: Response
  clientExtensionResults: ClientExtensionResults
}

export interface Response {
  clientDataJSON: string
  attestationObject: string
}

export interface ClientExtensionResults {}


export interface FinishResponse {
  flowId: string
  registrationComplete: boolean
  access_token: string;
}
