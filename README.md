🔐 Single Sign-On (SSO) Authentication System
📌 Project Overview

This project is a Single Sign-On (SSO) authentication server that allows users to authenticate once and securely access protected resources. It demonstrates OAuth2-style authentication using JWT, centralized login, and secure session handling.

🧩 Features

User registration and login

Secure password hashing using bcrypt

JWT-based authentication and authorization

Token-protected API routes

Centralized SSO server logic

Simple client interface for testing authentication flow

🛠️ Tech Stack

Backend: Node.js, Express.js

Authentication: JWT (JSON Web Tokens)

Security: bcrypt

Database: SQLite (sso.db)

Frontend: HTML (test client)

📂 Project Structure
├── node_modules/        # Installed dependencies
├── public/              # Static files
├── .env.ini             # Environment variables
├── client.html          # Sample client for SSO testing
├── package.json         # Project metadata & dependencies
├── package-lock.json    # Dependency lock file
├── server.js             # Main SSO server logic
├── sso.db               # SQLite database

⚙️ How It Works

User registers or logs in via the SSO server

Server validates credentials and generates a JWT

Token is sent to the client

Client uses the token to access protected routes

Middleware verifies JWT before granting access

▶️ Getting Started
Prerequisites

Node.js installed

npm package manager

Installation & Run
git clone https://github.com/your-username/sso-project.git
cd sso-project
npm install
node server.js


Open client.html in your browser to test the authentication flow.

🔐 Security Measures

Passwords stored as hashed values

JWT-based stateless authentication

Token validation middleware

Environment-based configuration

🎯 Use Cases

Central authentication service for multiple applications

Learning OAuth2 & SSO concepts

Backend authentication system practice

Full-stack authentication demos

🚧 Future Enhancements

Refresh token support

Role-based access control (RBAC)

OAuth provider login (Google, GitHub)

Multi-client application support

👨‍💻 Author

Jazz K
Built as part of full-stack and authentication system learning.
