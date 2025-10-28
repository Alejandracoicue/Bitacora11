import { Component } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { HttpClient, HttpClientModule } from '@angular/common/http';
import { Router } from '@angular/router';

@Component({
  selector: 'app-recuperar-contra',
  standalone: true,
  imports: [CommonModule, FormsModule, HttpClientModule],
  templateUrl: './recuperar-contra.component.html',
  styleUrls: ['./recuperar-contra.component.css']
})
export class RecuperarContraComponent {

  step: number = 1; // controla paso 1 o paso 2
  username: string = '';
  captchaValue: string = '';
  captchaKey: string = '';
  captchaImage: string = '';
  isCaptchaCorrect: boolean = false; // habilita botón Continuar

  newPassword: string = '';
  confirmPassword: string = '';
  errorMessage: string = '';
  successMessage: string = '';

  constructor(private http: HttpClient, private router: Router) {
    this.cargarCaptcha(); // cargar captcha al iniciar
  }

  // PASO 1: cargar captcha
  cargarCaptcha() {
    this.http.get('http://127.0.0.1:8000/api/get-captcha/').subscribe((res: any) => {
      this.captchaKey = res.captcha_key;
      this.captchaImage = 'http://127.0.0.1:8000'+res.captcha_image_url;
      this.captchaValue = '';
      this.isCaptchaCorrect = false;
    });
  }

  verificarCaptcha() {
    // habilita el botón si el usuario escribió algo
    this.isCaptchaCorrect = this.captchaValue.trim().length > 0;
  }

  continuar() {
    if (this.isCaptchaCorrect && this.username.trim() !== '') {
      this.step = 2; // pasa al formulario de nueva contraseña
      this.errorMessage = '';
      this.successMessage = '';
    }
  }

  // PASO 2: cambiar contraseña
  cambiarPassword() {
    this.errorMessage = '';
    this.successMessage = '';

    if (this.newPassword !== this.confirmPassword) {
      this.errorMessage = 'Las contraseñas no coinciden';
      return;
    }

    const body = {
      username: this.username,
      password: this.newPassword,
      captcha_key: this.captchaKey,
      captcha_value: this.captchaValue
    };

    this.http.post('http://127.0.0.1:8000/api/change-password/', body).subscribe({
      next: (res: any) => {
        this.successMessage = 'Contraseña cambiada correctamente. Redirigiendo al login...';
        setTimeout(() => {
          this.router.navigate(['/login']); 
        }, 2000);
      },
      error: (err) => {
        this.errorMessage = err.error?.error || 'Ocurrió un error al cambiar la contraseña';
        
        this.cargarCaptcha();
        this.step = 1; 
      }
    });
  }

}
