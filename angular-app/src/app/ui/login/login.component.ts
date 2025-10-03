import {Component, OnInit} from '@angular/core';
import {Router, RouterOutlet} from '@angular/router';
import {FormBuilder, ReactiveFormsModule, Validators} from '@angular/forms';
import {AuthService} from '../../service/auth.service';
import {RegistrationRequest} from '../../model/registration';
import {StartResponse} from '../../model/fido-registration-start';
import {UtilService} from '../../service/util.service';
import {FidoLogin} from '../../model/login';
import {StartLoginResponse} from '../../model/fido-login-start';
import {NgIf} from "@angular/common";
import {TwoFactorAuthComponent} from "../two-factor-auth/two-factor-auth.component";


@Component({
  selector: 'app-login',
  standalone: true,
  imports: [RouterOutlet, ReactiveFormsModule, NgIf, TwoFactorAuthComponent,],
  templateUrl: './login.component.html',
  styleUrl: './login.component.scss'
})
export class LoginComponent implements OnInit {

  formGroup = this._formBuilder.group({
    email: ['', Validators.required],
    password: ['', Validators.required]
  });
  twoFactorMethods: string[] = [];
  email = '';
  password = '';

  constructor(private _authService: AuthService, private _formBuilder: FormBuilder, private _utilService: UtilService, private router: Router) {
  }

  ngOnInit(): void {


  }

  async fetchTwoFactorMethods(): Promise<void> {
    try {
      let username = this.formGroup.value.email || '';
      const methods = await this._authService.getTwoFactorMethods(username).toPromise();
      this.twoFactorMethods = methods || [];
    } catch (error) {
      console.error('Error fetching 2FA methods:', error);
    }
  }


  async login(): Promise<void> {

    this.email = this.formGroup.value.email || '';
    this.password = this.formGroup.value.password || '';
    await this.fetchTwoFactorMethods();

    if (this.twoFactorMethods.length > 0) {

      console.log(this.twoFactorMethods);
      return;
    }

    this._authService.usernameAndPassword(this.email,this.password)
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


