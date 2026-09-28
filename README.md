# Secure JWT Authentication API

A secure and production-oriented RESTful Authentication API built with PHP, MySQL, and JSON Web Tokens (JWT).

This project provides a complete authentication system with secure password handling, JWT access and refresh tokens, OTP verification, role-based access control, rate limiting, password recovery, token revocation, and security logging.

---

## Features

### Authentication

* User registration
* Secure login
* JWT access tokens
* JWT refresh tokens
* Secure logout
* Token revocation
* Session management

### Email and OTP

* Email verification
* OTP generation and validation
* OTP expiration
* OTP attempt limits
* Password reset via OTP

### Security

* Password hashing using PHP's `password_hash()`
* Prepared SQL statements
* Input validation and sanitization
* JWT signature verification
* Token expiration
* Refresh-token rotation
* Rate limiting
* Brute-force protection
* Security headers
* Secure error responses
* Audit and security logging

### User Management

* User profile
* Change password
* Forgot password
* Reset password
* Role-Based Access Control (RBAC)
* Account and session management

---

## Tech Stack

| Technology | Purpose                   |
| ---------- | ------------------------- |
| PHP        | Backend API               |
| MySQL      | Database                  |
| JWT        | Authentication            |
| REST API   | API architecture          |
| PHPMailer  | Email delivery            |
| Composer   | PHP dependency management |
| XAMPP      | Local development         |

---

## Project Structure

```text
secure-jwt-auth/
│
├── api/
│   ├── auth/
│   │   ├── register.php
│   │   ├── login.php
│   │   ├── refresh.php
│   │   ├── logout.php
│   │   ├── verify_otp.php
│   │   └── forgot_password.php
│   │
│   ├── user/
│   │   ├── profile.php
│   │   └── change_password.php
│   │
│   └── middleware/
│       ├── auth.php
│       └── security.php
│
├── config/
│   ├── bootstrap.php
│   ├── database.php
│   └── jwt.php
│
├── includes/
│   ├── response.php
│   ├── validation.php
│   ├── logger.php
│   └── request_limiter.php
│
├── otp/
│   └── otp_service.php
│
├── database/
│   └── schema.sql
│
├── .env
├── .gitignore
├── composer.json
└── README.md
```

---

## Authentication Flow

```text
Client
   │
   │ Register / Login
   ▼
Authentication API
   │
   ├── Validate Request
   │
   ├── Verify Credentials
   │
   ├── Generate JWT
   │
   ▼
Access Token + Refresh Token
   │
   ├───────────────┐
   ▼               ▼
Protected API    Refresh API
   │               │
   │               ▼
   │         New Access Token
   │
   ▼
Authenticated Response
```

---

## JWT Token Strategy

The API uses two types of tokens.

### Access Token

A short-lived token used to access protected API endpoints.

```text
Authorization: Bearer <access_token>
```

### Refresh Token

A longer-lived token used to obtain a new access token without requiring the user to log in again.

Refresh tokens are stored and managed securely so they can be revoked when required.

---

## API Endpoints

### Authentication

| Method | Endpoint                        | Description               | Authentication |
| ------ | ------------------------------- | ------------------------- | -------------- |
| POST   | `/api/auth/register.php`        | Register user             | No             |
| POST   | `/api/auth/login.php`           | Login user                | No             |
| POST   | `/api/auth/refresh.php`         | Refresh access token      | Refresh Token  |
| POST   | `/api/auth/logout.php`          | Logout and revoke session | Yes            |
| POST   | `/api/auth/verify_otp.php`      | Verify OTP                | Depends        |
| POST   | `/api/auth/forgot_password.php` | Request password reset    | No             |

### User

| Method | Endpoint                        | Description      | Authentication |
| ------ | ------------------------------- | ---------------- | -------------- |
| GET    | `/api/user/profile.php`         | Get user profile | Yes            |
| POST   | `/api/user/change_password.php` | Change password  | Yes            |

---

## Installation

### 1. Clone the repository

```bash
git clone https://github.com/your-username/secure-jwt-auth.git
```

### 2. Enter the project directory

```bash
cd secure-jwt-auth
```

### 3. Install dependencies

```bash
composer install
```

### 4. Create the database

Create a MySQL database:

```sql
CREATE DATABASE secure_jwt_auth;
```

Import the database schema:

```text
database/schema.sql
```

---

## Environment Configuration

Create a `.env` file in the project root.

Example:

```env
APP_ENV=development

DB_HOST=localhost
DB_PORT=3306
DB_NAME=secure_jwt_auth
DB_USER=root
DB_PASSWORD=

JWT_SECRET=your-long-random-secret
JWT_ISSUER=secure-jwt-auth
JWT_AUDIENCE=secure-jwt-client

ACCESS_TOKEN_TTL=900
REFRESH_TOKEN_TTL=604800

MAIL_HOST=smtp.example.com
MAIL_PORT=587
MAIL_USERNAME=your-email@example.com
MAIL_PASSWORD=your-password
MAIL_ENCRYPTION=tls
MAIL_FROM_ADDRESS=your-email@example.com
MAIL_FROM_NAME=Secure JWT Auth
```

Never commit `.env` to GitHub.

---

## Password Security

Passwords are never stored as plain text.

PHP's password hashing API is used:

```php
password_hash($password, PASSWORD_DEFAULT);
```

During authentication:

```php
password_verify($password, $hashedPassword);
```

---

## Security Architecture

The API follows several security principles.

### Password Protection

* Strong password hashing
* No plain-text password storage
* Password verification through secure hashing APIs

### SQL Injection Protection

Database queries use prepared statements instead of directly concatenating user input.

### JWT Protection

JWTs are:

* Cryptographically signed
* Validated before use
* Checked for expiration
* Issued with controlled claims
* Rejected when invalid or revoked

### Rate Limiting

Authentication endpoints are protected against excessive requests and brute-force attempts.

### OTP Protection

OTP functionality includes:

* Expiration
* Attempt limits
* Secure generation
* Validation
* Request throttling

### Token Revocation

Sessions and refresh tokens can be revoked during logout or other security events.

---

## Testing

API endpoints can be tested using:

* Postman
* Insomnia
* cURL

Example login request:

```http
POST /api/auth/login.php
Content-Type: application/json
```

Example request body:

```json
{
    "email": "user@example.com",
    "password": "your-password"
}
```

Example authenticated request:

```http
Authorization: Bearer YOUR_ACCESS_TOKEN
```

---

## Example Response

### Successful Login

```json
{
    "success": true,
    "message": "Login successful",
    "data": {
        "access_token": "JWT_ACCESS_TOKEN",
        "refresh_token": "REFRESH_TOKEN",
        "token_type": "Bearer",
        "expires_in": 900
    }
}
```

### Error Response

```json
{
    "success": false,
    "message": "Invalid credentials"
}
```

---

## Development Roadmap

* [x] Project architecture
* [ ] Database schema
* [ ] Environment configuration
* [ ] Database connection
* [ ] JWT service
* [ ] User registration
* [ ] User login
* [ ] Access token validation
* [ ] Refresh token system
* [ ] Logout and token revocation
* [ ] OTP verification
* [ ] Email integration
* [ ] Password reset
* [ ] Rate limiting
* [ ] RBAC
* [ ] Audit logging
* [ ] Security hardening
* [ ] API documentation
* [ ] Testing

---

## Security Notice

This project is intended for learning and development purposes. Before using an authentication system in production, perform a proper security review, configure secure secrets and cookies/transport appropriately, and test all authentication and authorization flows.

Never expose:

```text
.env
JWT_SECRET
Database passwords
SMTP passwords
Private keys
API credentials
```

---

## Author

**Mohit Sharma**

Full Stack Developer

---

## License

This project is available for educational and development purposes.
