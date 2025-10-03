import { mergeApplicationConfig, ApplicationConfig } from '@angular/core';
import { provideServerRendering } from '@angular/platform-server';
import { appConfig } from './app.config';
import {JWT_OPTIONS, JwtHelperService} from "@auth0/angular-jwt";

const serverConfig: ApplicationConfig = {
  providers: [
    provideServerRendering(),
  ]
};

export const config = mergeApplicationConfig(appConfig, serverConfig);
