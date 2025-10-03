import {Component, OnInit} from '@angular/core';
import {AuthService} from '../../service/auth.service';
import {User} from '../../model/user';
import {NgIf} from '@angular/common';
import {Router} from '@angular/router';
import {TokenService} from '../../service/token.service';

@Component({
  selector: 'app-welcome',
  standalone: true,
  imports: [NgIf],
  templateUrl: './welcome.component.html',
  styleUrl: './welcome.component.scss'
})
export class WelcomeComponent implements OnInit {


  firstName: string | null = null;
  lastName: string | null = null;
  displayName: string | null = null;

  constructor(private authService: AuthService, private router: Router, private tokenService: TokenService) {
  }

  ngOnInit(): void {
    // Get user information from the bearer token
    this.firstName = this.tokenService.getFirstName();
    this.lastName = this.tokenService.getLastName();
    this.displayName = this.tokenService.getFullName();

    console.log('User info from token:', {
      firstName: this.firstName,
      lastName: this.lastName,
      displayName: this.displayName
    });
  }

  signOut() {

    this.router.navigate(['/login'])

    localStorage.clear();
  }

  createPasskey() {

    this.router.navigate(['/register'])
  }

  setupOtp() {
    this.router.navigate(['/otp-registration'])
  }

}
