import {Component, Input} from '@angular/core';
import {FormBuilder, FormsModule} from "@angular/forms";
import {NgForOf, NgIf, UpperCasePipe} from "@angular/common";
import {AuthService} from "../../service/auth.service";
import {UtilService} from "../../service/util.service";
import {Router} from "@angular/router";
import {FidoLogin} from "../../model/login";
import {StartLoginResponse} from "../../model/fido-login-start";

@Component({
  selector: 'app-two-factor-auth',
  standalone: true,
  imports: [
    FormsModule,
    UpperCasePipe,
    NgForOf,
    NgIf
  ],
  templateUrl: './two-factor-auth.component.html',
  styleUrl: './two-factor-auth.component.scss'
})
export class TwoFactorAuthComponent {

  @Input() twoFactorMethods: string[] = [];
  selectedMethod: string = '';
  otpCode: string = '';
  @Input() username: string = '';
  @Input() password: string = '';
  reference?: string;

  constructor(private _authService: AuthService,
              private _utilService: UtilService,
              private router: Router) {
  }

  async onContinue(): Promise<void> {
    if (this.selectedMethod) {

      if (this.selectedMethod === 'otp' && !this.otpCode) {
        alert('Please enter your OTP.');
        return;
      }

      console.log('Selected 2FA method:', this.selectedMethod, this.username, this.password);
      if (this.selectedMethod == 'email') {
        await this.loginWithEmail();
        return;
      }
      if (this.selectedMethod == 'webauthn') {
        await this.loginWithWebAuthn();
        return;
      } else if (this.selectedMethod == 'otp') {

        this._authService.otpLogin(this.username, this.password, this.otpCode)
          .subscribe({
            next: value => {
              console.log(value);
              console.log('Login successful....')
              localStorage.setItem('bearerToken', value.access_token);
              this.router.navigate(['/welcome'])
            },
            error: err => {
              console.log(err);
            },
          })
        return;
      }
    } else {
      alert('Please select a 2FA method to continue.');
    }
  }

  async loginWithWebAuthn(): Promise<void> {


    let request = new FidoLogin();
    request.username = this.username;
    this._authService.fidoStartLogin(request)
      .subscribe({
        next: value => {
          console.log(value);
          this.createCredentials(value);
        },
        error: err => {
          console.log(err);
        },
      })

  }

  async createCredentials(settings: StartLoginResponse) {

    let creds: { type: any; id: Uint8Array; }[] = [];
    settings.assertionRequest.publicKeyCredentialRequestOptions.allowCredentials.forEach(
      (cred: { type: any; id: any; }) => {
        const result = {
          type: cred.type,
          id: this._utilService.toByteArray(cred.id)
        }
        creds.push(result)
      }
    )

    const publicKey: PublicKeyCredentialRequestOptions = {
      challenge: this._utilService.toByteArray(settings.assertionRequest.publicKeyCredentialRequestOptions.challenge),
      allowCredentials: creds

    }
    let credential = await this.createCreedential(publicKey);
    console.log(credential)
    this.finishRegistration(settings, credential);

  }

  finishRegistration(settings: StartLoginResponse, credential: any | null) {

    if (!credential) {
      return;
    }
    const attestationResponse = credential.response as any;

    const cred = {
      id: credential.id,
      rawId: this._utilService.fromByteArray(new Uint8Array(credential.rawId)),
      type: credential.type,
      response: {
        clientDataJSON: this._utilService.fromByteArray(new Uint8Array(attestationResponse.clientDataJSON)),
        authenticatorData: this._utilService.fromByteArray(new Uint8Array(attestationResponse.authenticatorData)),
        signature: this._utilService.fromByteArray(new Uint8Array(attestationResponse.signature))
      },
      clientExtensionResults: credential.getClientExtensionResults ? credential.getClientExtensionResults() : {}
    };
    const finishRequest = {
      reference: settings.reference,
      credential: JSON.stringify(cred)

    };

    this._authService.webauthnLogin(this.username, this.password, finishRequest.reference, finishRequest.credential)
      .subscribe({
        next: value => {
          console.log(value);
          console.log('Login successful....')
          localStorage.setItem('bearerToken', value.access_token);
          this.router.navigate(['/welcome'])
        },
        error: err => {
          console.log(err);
        },
      })

  }

  createCreedential(publicKey: PublicKeyCredentialRequestOptions): Promise<any | null> {
    return navigator.credentials.get({publicKey}) // Note: 'publicKey' is already correctly used here
      .then((newCredentialInfo) => {
        console.log('SUCCESS', newCredentialInfo);
        return newCredentialInfo; // Explicitly cast to PublicKeyCredential
      })
      .catch((error) => {
        console.log('FAIL', error);
        return null; // You can also rethrow the error or handle it differently
      });
  }

  async loginWithEmail() {

    if (!this.reference) {
      this._authService.sendCode(this.username, 'email')
        .subscribe({
          next: value => {
            console.log(value);
            this.reference = value.reference;
          },
          error: err => {
            console.log(err);
          },
        })
    } else {
      if (!this.otpCode) {
        alert('Please enter your OTP.');
        return;
      }
      this._authService.emailLogin(this.username, this.password, this.otpCode,this.reference || '')
        .subscribe({
          next: value => {
            console.log(value);
            console.log('Login successful....')
            localStorage.setItem('bearerToken', value.access_token);
            this.router.navigate(['/welcome'])
          },
          error: err => {
            console.log(err);
          },
        })

    }


  }
}
