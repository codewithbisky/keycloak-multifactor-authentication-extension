import { Routes } from '@angular/router';
import { AppComponent } from './app.component';
import { LoginComponent } from './ui/login/login.component';
import { RegistrationComponent } from './ui/registration/registration.component';
import { WelcomeComponent } from './ui/welcome/welcome.component';
import { OtpRegistrationComponent } from './ui/otp-registration/otp-registration.component';

export const routes: Routes = [
    {path: '', redirectTo: 'login', pathMatch: 'full'},
    {path: 'home', component: LoginComponent },
    {path: 'register', component: RegistrationComponent},
    {path: 'login', component: LoginComponent},
    {path: 'welcome', component: WelcomeComponent},
    {path: 'otp-registration', component: OtpRegistrationComponent},
];
