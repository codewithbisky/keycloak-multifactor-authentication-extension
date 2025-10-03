import { Injectable } from '@angular/core';
import { JwtHelperService } from '@auth0/angular-jwt';

@Injectable({
  providedIn: 'root',
})
export class TokenService {
  constructor(private jwtHelper: JwtHelperService) {}

  getDecodedToken(token: string): any {
    try {
      return this.jwtHelper.decodeToken(token);
    } catch (error) {
      console.error('Error decoding token:', error);
      return null;
    }
  }

  getUsername(): string | null {

    const token = localStorage.getItem('bearerToken') ||'';
    const decodedToken = this.getDecodedToken(token);
    return decodedToken ? decodedToken.preferred_username : null;
  }

  getFullName(): string | null {
    const token = localStorage.getItem('bearerToken') ||'';
    const decodedToken = this.getDecodedToken(token);
    return decodedToken ? decodedToken.name : null;
  }

  getFirstName(): string | null {
    const token = localStorage.getItem('bearerToken') ||'';
    const decodedToken = this.getDecodedToken(token);
    return decodedToken ? decodedToken.given_name : null;
  }

  getLastName(): string | null {
    const token = localStorage.getItem('bearerToken') ||'';
    const decodedToken = this.getDecodedToken(token);
    return decodedToken ? decodedToken.family_name : null;
  }

  getUserIdentifier(): string | null {
    const token = localStorage.getItem('bearerToken') ||'';
    const decodedToken = this.getDecodedToken(token);
    return decodedToken ? decodedToken.sub : null;
  }
}
