import {Inject, Injectable, PLATFORM_ID} from "@angular/core";
import {Observable} from "rxjs";
import {HttpClient, HttpHeaders, HttpParams} from "@angular/common/http";
import {Token} from "../model/Token";
import {RegistrationRequest} from "../model/registration";
import {StartResponse} from "../model/fido-registration-start";
import {FinishResponse} from "../model/fido-registration-finish";
import {FidoLogin} from "../model/login";
import {StartLoginResponse} from "../model/fido-login-start";
import {User} from "../model/user";
import {isPlatformBrowser} from "@angular/common";
import {TokenService} from "./token.service";
import {SendCode} from "../model/SendCode";
import {OtpSecretData, OtpSubmission} from "../model/otp-registration";


@Injectable({providedIn: 'root'})
export class AuthService {

  keycloakRealm = 'security';
  constructor(private http: HttpClient, @Inject(PLATFORM_ID) private platformId: object
    , private _tokenService: TokenService) {
  }


  startChallenge(request: RegistrationRequest) {
    const userId = this._tokenService.getUserIdentifier();
    return this.http.post<StartResponse>(`/keycloak/realms/${this.keycloakRealm}/two-factor-auth/webauth/${userId}/register/start`, request, {
      headers: {"Authorization": "Bearer " + localStorage.getItem('bearerToken') || ''}
    });
  }

  finishSetUp(request: any) {
    const userId = this._tokenService.getUserIdentifier();
    return this.http.post<FinishResponse>(`/keycloak/realms/${this.keycloakRealm}/two-factor-auth/webauth/${userId}/register/finish`, request, {
      headers: {"Authorization": "Bearer " + localStorage.getItem('bearerToken') || ''}
    });
  }


  fidoStartLogin(request: FidoLogin) {

    return this.http.post<StartLoginResponse>(`/keycloak/realms/${this.keycloakRealm}/two-factor-auth/webauth/login/start`, request);
  }


  getCurrentUser() {

    let token = null;
    if (isPlatformBrowser(this.platformId)) {
      token = localStorage.getItem('bearerToken');

    }
    let headers = new HttpHeaders();

    if (token) {
      headers = headers.set('Authorization', `Bearer ${token}`);
    }

    return this.http.get<User>(`/auth/user`, {headers});
  }

  getTwoFactorMethods(username: string): Observable<string[]> {
    return this.http.get<string[]>(`/keycloak/realms/${this.keycloakRealm}/two-factor-auth/methods?username=${username}`);
  }


  webauthnLogin(username: string, password: string, reference: string, credential: string): Observable<Token> {

    const headers = new HttpHeaders({
      'Content-Type': 'application/x-www-form-urlencoded',
    });
    const body = new HttpParams()
      .set('client_id', 'authenticationClientId')
      .set('password', password)
      .set('username', username)
      .set('grant_type', 'password')
      .set('credential', credential)
      .set('2nd_factor_type', 'webauthn')
      .set('reference', reference);
    return this.http.post<Token>(`/keycloak/realms/${this.keycloakRealm}/protocol/openid-connect/token`, body.toString(), {headers});
  }


  otpLogin(username: string, password: string, otp: string): Observable<Token> {

    const headers = new HttpHeaders({
      'Content-Type': 'application/x-www-form-urlencoded',
    });
    const body = new HttpParams()
      .set('client_id', 'authenticationClientId')
      .set('password', password)
      .set('username', username)
      .set('grant_type', 'password')
      .set('2nd_factor_type', 'otp')
      .set('otp', otp);
    return this.http.post<Token>(`/keycloak/realms/${this.keycloakRealm}/protocol/openid-connect/token`, body.toString(), {headers});
  }


  emailLogin(username: string, password: string, code: string, reference: string): Observable<Token> {

    const headers = new HttpHeaders({
      'Content-Type': 'application/x-www-form-urlencoded',
    });
    const body = new HttpParams()
      .set('client_id', 'authenticationClientId')
      .set('password', password)
      .set('username', username)
      .set('grant_type', 'password')
      .set('reference', reference)
      .set('verification_code', code)
      .set('2nd_factor_type', 'email');
    return this.http.post<Token>(`/keycloak/realms/${this.keycloakRealm}/protocol/openid-connect/token`, body.toString(), {headers});
  }


  sendCode(username: string, type: string): Observable<SendCode> {

    const params = new HttpParams()
      .set('username', username)
      .set('2nd_factor_type', type);
    return this.http.post<SendCode>(`/keycloak/realms/${this.keycloakRealm}/two-factor-auth/send`, null,{params:params});
  }


  usernameAndPassword(username: string, password: string): Observable<Token> {

    const headers = new HttpHeaders({
      'Content-Type': 'application/x-www-form-urlencoded',
    });
    const body = new HttpParams()
      .set('client_id', 'authenticationClientId')
      .set('password', password)
      .set('username', username)
      .set('grant_type', 'password');
    return this.http.post<Token>(`/keycloak/realms/${this.keycloakRealm}/protocol/openid-connect/token`, body.toString(), {headers});
  }

  // OTP Registration methods
  generateOtpSecret(): Observable<OtpSecretData> {
    const userId = this._tokenService.getUserIdentifier();
    return this.http.post<OtpSecretData>(
      `/keycloak/realms/${this.keycloakRealm}/two-factor-auth/manage-2fa/${userId}/totp/generate`,
      {},
      {
        headers: {"Authorization": "Bearer " + localStorage.getItem('bearerToken') || ''}
      }
    );
  }

  completeOtpRegistration(submission: OtpSubmission): Observable<any> {
    const userId = this._tokenService.getUserIdentifier();
    return this.http.post(
      `/keycloak/realms/${this.keycloakRealm}/two-factor-auth/manage-2fa/${userId}/totp/complete`,
      submission,
      {
        headers: {"Authorization": "Bearer " + localStorage.getItem('bearerToken') || ''}
      }
    );
  }

}
