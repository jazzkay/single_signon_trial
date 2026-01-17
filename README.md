This project is a Single Sign-On (SSO) authentication server built to enable users to securely authenticate once and access multiple applications without repeated logins. It follows OAuth2-style authentication principles using JWT tokens for stateless and secure session management.

🚀 Features

User registration and login

Secure password hashing

JWT-based authentication & authorization

Token validation and protected routes

Centralized authentication for multiple client apps

Scalable and stateless architecture

🛠 Tech Stack

Backend: Node.js, Express.js

Authentication: JWT (JSON Web Tokens)

Security: bcrypt for password hashing

Database: SQLite

API Testing: Postman

⚙️ How It Works

User registers or logs in via the SSO server

Server verifies credentials and issues a JWT

Client applications use the JWT for authentication

Protected routes validate tokens before granting access

📂 Project Structure
/routes        → Authentication routes  
/controllers  → Business logic  
/models       → Database models  
/middleware   → JWT verification  
/database     → SQLite configuration  

▶️ Getting Started
Prerequisites

Node.js installed

npm package manager

Installation
git clone https://github.com/your-username/sso-project.git
cd sso-project
npm install
npm start

🔐 Security Highlights

Passwords hashed using bcrypt

JWT expiration and verification

Middleware-based route protection

🎯 Use Cases

Central login system for multiple web apps

Enterprise authentication services

Learning OAuth2 and authentication workflows

📌 Future Enhancements

Refresh token implementation

Role-based access control (RBAC)

OAuth provider integration (Google, GitHub)

👨‍💻 Author

Jazz K
Built as part of full-stack and authentication system learning.
