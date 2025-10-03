import {Component, OnInit} from '@angular/core';
import {RouterOutlet} from '@angular/router';
import {AuthService} from "./service/auth.service";
import {FormBuilder, ReactiveFormsModule, Validators} from '@angular/forms';
import {UtilService} from './service/util.service';

// import { fromByteArray } from 'base64-js';


@Component({
  selector: 'app-root',
  standalone: true,
  imports: [RouterOutlet, ReactiveFormsModule,],
  templateUrl: './app.component.html',
  styleUrl: './app.component.scss'
})
export class AppComponent implements OnInit {

  formGroup = this._formBuilder.group({
    fullName: ['', Validators.required],
    email: ['', Validators.required]
  });

  constructor(private _authService: AuthService
    , private _formBuilder: FormBuilder
    ,private _utilService: UtilService) {
  }

  ngOnInit(): void {


  }

}
