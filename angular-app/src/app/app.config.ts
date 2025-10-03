import {ApplicationConfig} from '@angular/core';
import {provideRouter} from '@angular/router';

import {routes} from './app.routes';
import {provideClientHydration} from '@angular/platform-browser';
import {provideHttpClient, withFetch} from "@angular/common/http";
import {FacebookLoginProvider, SocialAuthServiceConfig} from "@abacritt/angularx-social-login";
import {JWT_OPTIONS, JwtHelperService} from "@auth0/angular-jwt";

export const appConfig: ApplicationConfig = {
  providers: [provideRouter(routes), provideClientHydration(),
    provideHttpClient(withFetch(), ),
    {
      provide: 'SocialAuthServiceConfig',
      useValue: {
        autoLogin: false,
        providers: [
          {
            id: FacebookLoginProvider.PROVIDER_ID,
            provider: new FacebookLoginProvider('398158831124098')
          }
        ],
        onError: (err) => {
          console.error(err);
        }
      } as SocialAuthServiceConfig,
    },
    JwtHelperService,
    { provide: JWT_OPTIONS, useValue: {} },
  ]
};
