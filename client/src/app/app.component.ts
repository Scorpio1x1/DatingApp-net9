import { HttpClient } from '@angular/common/http';
import { Component, inject, OnInit } from '@angular/core';
import { RouterOutlet } from '@angular/router';

@Component({
  selector: 'app-root',
  imports: [RouterOutlet],
  templateUrl: './app.component.html',
  styleUrl: './app.component.css'
})
export class AppComponent implements OnInit {
  
  http = inject(HttpClient);
  title = 'Dating app';
  users: any;
  
  ngOnInit(): void {
    this.http.get('https://localhost:5001/api/users').subscribe({
      next: (response) => {this.users = response},
      error: (e) => {console.log(e)},
      complete: () => {console.log("completed")}
    })
  }
}
