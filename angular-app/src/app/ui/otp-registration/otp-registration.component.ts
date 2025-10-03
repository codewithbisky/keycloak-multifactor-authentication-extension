import {Component, OnInit} from '@angular/core';
import {FormBuilder, ReactiveFormsModule, Validators} from '@angular/forms';
import {AuthService} from '../../service/auth.service';
import {TokenService} from "../../service/token.service";
import {Router} from '@angular/router';
import {OtpSecretData, OtpSubmission} from '../../model/otp-registration';
import {NgIf} from '@angular/common';

@Component({
  selector: 'app-otp-registration',
  standalone: true,
  imports: [ReactiveFormsModule, NgIf],
  templateUrl: './otp-registration.component.html',
  styleUrl: './otp-registration.component.scss'
})
export class OtpRegistrationComponent implements OnInit {

  formGroup = this._formBuilder.group({
    deviceName: ['', Validators.required],
    otpCode: ['', [Validators.required, Validators.pattern(/^\d{6}$/)]]
  });

  otpSecret: OtpSecretData | null = null;
  qrCodeDataUrl: string = '';
  isLoading = false;
  errorMessage = '';
  successMessage = '';

  constructor(
    private _authService: AuthService,
    private _formBuilder: FormBuilder,
    private _tokenService: TokenService,
    private _router: Router
  ) {
  }

  ngOnInit(): void {
    this.generateOtpSecret();
  }

  generateOtpSecret(): void {
    this.isLoading = true;
    this.errorMessage = '';

    this._authService.generateOtpSecret()
      .subscribe({
        next: value => {
          console.log('OTP Secret generated:', value);
          console.log('QR Code data:', value.totpSecretQRCode);
          console.log('Encoded secret:', value.encodedTotpSecret);

          this.otpSecret = value;

          // Add data URI prefix if not present
          if (value.totpSecretQRCode) {
            if (value.totpSecretQRCode.startsWith('data:image')) {
              this.qrCodeDataUrl = value.totpSecretQRCode;
            } else {
              this.qrCodeDataUrl = `data:image/png;base64,${value.totpSecretQRCode}`;
            }
            console.log('QR Code Data URL:', this.qrCodeDataUrl.substring(0, 50) + '...');
          } else {
            console.error('QR code data is missing from response');
            this.errorMessage = 'QR code data is missing. Please check backend response.';
          }

          this.isLoading = false;
        },
        error: err => {
          console.error('Error generating OTP secret:', err);
          console.error('Error details:', err.error);
          console.error('Error status:', err.status);
          this.errorMessage = 'Failed to generate OTP secret. Please try again.';
          this.isLoading = false;
        },
      });
  }

  completeRegistration(): void {
    if (!this.formGroup.valid || !this.otpSecret) {
      return;
    }

    this.isLoading = true;
    this.errorMessage = '';
    this.successMessage = '';

    const submission: OtpSubmission = {
      device_name: this.formGroup.value.deviceName || '',
      encoded_totp_secret: this.otpSecret.encodedTotpSecret,
      totp_initial_code: this.formGroup.value.otpCode || '',
      should_overwrite: false
    };

    this._authService.completeOtpRegistration(submission)
      .subscribe({
        next: () => {
          console.log('OTP registration completed successfully');
          this.successMessage = 'OTP registration completed successfully!';
          this.isLoading = false;

          // Navigate back to welcome page after 2 seconds
          setTimeout(() => {
            this._router.navigate(['/welcome']);
          }, 2000);
        },
        error: err => {
          console.error('Error completing OTP registration:', err);
          this.errorMessage = err.error?.message || 'Failed to complete OTP registration. Please verify your code and try again.';
          this.isLoading = false;
        },
      });
  }

  cancel(): void {
    this._router.navigate(['/welcome']);
  }

  onImageError(event: any): void {
    console.error('QR Code image failed to load:', event);
    console.error('Image src:', this.qrCodeDataUrl);
    this.errorMessage = 'Failed to load QR code image. Please use manual entry.';
  }
}

