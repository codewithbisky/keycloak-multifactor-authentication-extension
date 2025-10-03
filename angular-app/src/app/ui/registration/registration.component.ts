import {Component, OnInit} from '@angular/core';
import {RouterOutlet} from '@angular/router';
import {FormBuilder, ReactiveFormsModule, Validators} from '@angular/forms';
import { AuthService } from '../../service/auth.service';
import { UtilService } from '../../service/util.service';
import { StartResponse } from '../../model/fido-registration-start';
import { RegistrationRequest } from '../../model/registration';
import {TokenService} from "../../service/token.service";
// import { fromByteArray } from 'base64-js';


@Component({
  selector: 'app-registration',
  standalone: true,
  imports: [RouterOutlet, ReactiveFormsModule,],
  templateUrl: './registration.component.html',
  styleUrl: './registration.component.scss'
})
export class RegistrationComponent implements OnInit {

  formGroup = this._formBuilder.group({
    fullName: ['', Validators.required],
    email: ['', Validators.required]
  });

  constructor(private _authService: AuthService
    , private _formBuilder: FormBuilder
    , private _tokenService: TokenService
    ,private _utilService: UtilService) {
  }

  ngOnInit(): void {

    let fullname = this._tokenService.getFullName()
    let username = this._tokenService.getUsername()

    console.log('DETAILS ',fullname,username)

    this.formGroup.patchValue({
      fullName: fullname || '',
      email: username || '',
    });

  }


  registration(): void {

   let request = new RegistrationRequest();
    request.fullName= this.formGroup.value.fullName;
    request.email= this.formGroup.value.email;
    this._authService.startChallenge(request)
    .subscribe({
      next: value => {
        console.log(value);
        this.registerCredentials(value);
      },
      error: err => {
        console.log(err);
      },
    })

  }

  async registerCredentials(settings: StartResponse){


    const publicKey:PublicKeyCredentialCreationOptions = {
      challenge: this._utilService.toByteArray(settings.credentialCreationOptions.challenge),
      rp: {
        name: settings.credentialCreationOptions.rp.name,
        id: settings.credentialCreationOptions.rp.id,
      },
      user: {
        name: settings.credentialCreationOptions.user.name,
        displayName: settings.credentialCreationOptions.user.displayName,
        id: this._utilService.toByteArray(settings.credentialCreationOptions.user.id)
      },
      pubKeyCredParams: settings.credentialCreationOptions.pubKeyCredParams,
      attestation: settings.credentialCreationOptions.attestation
    }
      console.log(publicKey)
      let credential =await this.createCredential(publicKey);
      console.log(credential)
      this.finishRegistration(settings,credential);



  }

   finishRegistration(settings: StartResponse, credential:PublicKeyCredential| null) {


    if(!credential){
      return;
    }

    const attestationResponse = credential.response as AuthenticatorAttestationResponse;

    const credentialObject = {
      id: credential.id,
      rawId: this._utilService.fromByteArray(new Uint8Array(credential.rawId)),
      type: credential.type,
      response: {
        clientDataJSON: this._utilService.fromByteArray(new Uint8Array(attestationResponse.clientDataJSON)),
        attestationObject: this._utilService.fromByteArray(new Uint8Array(attestationResponse.attestationObject))
      },
      clientExtensionResults: credential.getClientExtensionResults ? credential.getClientExtensionResults() : {}
    };
     const finishRequest = {
      reference: settings.reference,
       jsonResponse: settings.jsonResponse,
       credential: JSON.stringify(credentialObject)
    };

    console.log(finishRequest)
    this._authService.finishSetUp(finishRequest)
    .subscribe({

      next: value => {
        console.log(value);

      },
      error: err => {
        console.log(err);
      },
    })

  }

  createCredential(publicKey: PublicKeyCredentialCreationOptions): Promise<PublicKeyCredential | null> {
    return navigator.credentials.create({ publicKey }) // Note: 'publicKey' is already correctly used here
      .then((newCredentialInfo) => {
        console.log('SUCCESS', newCredentialInfo);
        return newCredentialInfo as PublicKeyCredential; // Explicitly cast to PublicKeyCredential
      })
      .catch((error) => {
        console.log('FAIL', error);
        return null; // You can also rethrow the error or handle it differently
      });
  }

}
