# Secure JWT Authentication API

A production-oriented authentication system built with PHP, MySQL and JWT.

This project is designed with security-first principles including short-lived access tokens, refresh-token rotation, token revocation, OTP verification, rate limiting, RBAC, session management, password reset and security auditing.

---

## Features

### Authentication

- User registration
- Email verification
- Login with email and password
- Login OTP verification
- Secure logout
- Logout from all devices
- Change password
- Forgot password
- Password reset
- Access token authentication
- Refresh token authentication

### JWT Security

- Short-lived access tokens
- Long-lived refresh tokens
- JWT signature verification
- Issuer validation
- Audience validation
- Expiration validation
- Issued-at validation
- Not-before validation
- Clock-skew protection
- Token type validation
- Unique JTI
- Token version validation
- Database-backed access-token revocation
- Refresh-token rotation
- Refresh-token family tracking
- Refresh-token reuse detection

### Refresh Token Security

- Refresh tokens are never stored as plaintext
- SHA-256 token hashing
- Refresh token sessions stored in database
- Token family support
- Parent/replacement token tracking
- Token revocation
- Reuse detection
- Complete token-family revocation
- Logout session revocation

### Password Security

- `password_hash()`
- `password_verify()`
- Password rehash support
- Password length validation
- Password change protection
- Password reset tokens
- Reset token hashing
- Reset token expiration
- All sessions revoked after password reset

### OTP Security

- Real email OTP delivery
- PHPMailer SMTP
- Hashed OTP storage
- 6-digit OTP
- OTP expiration
- Maximum verification attempts
- OTP resend cooldown
- Previous OTP invalidation
- Separate OTP flows for:
  - Email verification
  - Login verification
  - Password reset

### Rate Limiting

- Global API rate limiting
- IP-based rate limiting
- Endpoint-based rate limiting
- Email-based authentication limits
- Login brute-force protection
- OTP resend protection
- Password reset protection
- Database-backed rate limiter

### Authorization

- Authentication middleware
- Role-based access control
- User role
- Admin role
- Account status validation
- Active account validation
- Email verification requirement

### Account Protection

- Active account validation
- Blocked account protection
- Suspended account protection
- Email verification requirement
- Token version based revocation
- Logout-all-devices
- Session management

### HTTP Security

- CORS protection
- Allowed-origin validation
- Security headers
- HTTPS enforcement in production
- HSTS in production
- Request method validation
- Request body size limit
- JSON content-type validation
- No-store cache headers

### Logging

Security events are recorded through audit logging.

The system avoids logging sensitive information such as:

- Passwords
- OTP values
- JWT access tokens
- Refresh tokens
- Reset tokens

---

# Architecture

```text
Frontend
   |
   | HTTPS / TLS
   v
PHP API
   |
   +--> CORS
   |
   +--> Security Headers
   |
   +--> Request Method Validation
   |
   +--> Request Size Validation
   |
   +--> Global Rate Limiting
   |
   +--> Input Validation
   |
   v
Authentication Middleware
   |
   v
JWT Verification
   |
   +--> Signature
   +--> Issuer
   +--> Audience
   +--> Expiration
   +--> Issued At
   +--> Not Before
   +--> JTI
   +--> Token Type
   +--> Token Version
   |
   v
Database User Verification
   |
   +--> Account Status
   +--> Email Verification
   +--> Token Version
   |
   v
Authorization / RBAC
   |
   v
Protected API










secure-jwt-auth/
│
├── api/
│   │
│   ├── auth/
│   │   ├── register.php
│   │   ├── login.php
│   │   ├── refresh.php
│   │   ├── logout.php
│   │   ├── logout-all.php
│   │   ├── forgot-password.php
│   │   ├── reset-password.php
│   │   └── change-password.php
│   │
│   ├── middleware/
│   │   ├── auth.php
│   │   ├── jwt.php
│   │   ├── role.php
│   │   ├── refresh_token.php
│   │   └── security.php
│   │
│   ├── otp/
│   │   ├── resend-email.php
│   │   ├── verify-email.php
│   │   ├── verify-login.php
│   │   ├── resend-password-reset.php
│   │   └── verify-password-reset.php
│   │
│   ├── users/
│   │   ├── me.php
│   │   └── update-profile.php
│   │
│   └── sessions/
│       ├── list.php
│       ├── revoke.php
│       └── revoke-all.php
│
├── config/
│   ├── bootstrap.php
│   ├── database.php
│   ├── app.php
│   ├── jwt.php
│   ├── mail.php
│   ├── cors.php
│   └── security.php
│
├── includes/
│   ├── response.php
│   ├── validation.php
│   ├── rate_limiter.php
│   ├── request_limiter.php
│   └── logger.php
│
├── database/
│   └── rate_limits.sql
│
├── logs/
│
├── vendor/
│
├── .env
├── .env.example
├── .gitignore
├── composer.json
├── composer.lock
└── README.md




Authentication Flow
Registration
POST /api/auth/register.php
        |
        v
Validate Input
        |
        v
Rate Limit
        |
        v
Create User
        |
        v
Generate Email OTP
        |
        v
Send OTP Email
        |
        v
User Verifies OTP
        |
        v
Account Activated
Login Flow
POST /api/auth/login.php
        |
        v
Validate Credentials
        |
        v
Password Verification
        |
        v
Generate Login OTP
        |
        v
Send OTP
        |
        v
POST /api/otp/verify-login.php
        |
        v
Generate Access Token
+
Generate Refresh Token

No access or refresh token is issued before successful login OTP verification.

Refresh Flow
Access Token Expired
        |
        v
Send Refresh Token
        |
        v
Verify JWT
        |
        v
Check Database Session
        |
        v
Check Token Family
        |
        v
Rotate Refresh Token
        |
        v
Revoke Old Token
        |
        v
Return New Tokens
Logout Flow

Normal logout:

Access Token
+
Refresh Token
        |
        v
Revoke Current Refresh Session

The current access token remains valid until its expiration.

For immediate access-token invalidation:

logout-all.php

This increments:

users.token_version

and revokes all refresh sessions.

Password Change

When the password is changed:

New Password
      |
      v
Password Hash
      |
      v
Increment token_version
      |
      v
Revoke all refresh tokens
      |
      v
Invalidate reset sessions

Existing access tokens become invalid immediately.

Password Reset
Forgot Password
      |
      v
Email OTP
      |
      v
Verify OTP
      |
      v
Generate Reset Token
      |
      v
Set New Password
      |
      v
Increment token_version
      |
      v
Revoke All Sessions
OTP Security

OTP configuration:

Length: 6 digits
Expiration: 5 minutes
Maximum attempts: 5
Resend cooldown: 60 seconds

OTP values are never stored as plaintext.

OTP verification uses a hash comparison.

Rate Limiting

The API uses multiple layers of rate limiting.

Global

Default:

60 requests / 60 seconds
Login
5 failed attempts / 15 minutes

Additional IP/email limits are applied to authentication endpoints.

OTP

OTP endpoints use:

Email-based limits
IP-based limits
Resend cooldown
Maximum verification attempts

The rate limiter is database-backed.











Production Checklist

Before deployment:

 Use HTTPS
 Generate a new JWT secret
 Configure SMTP
 Configure production database
 Configure exact CORS origin
 Set APP_ENV=production
 Set APP_DEBUG=false
 Protect .env
 Disable directory listing
 Configure secure cookies if cookies are used
 Configure firewall
 Enable database backups
 Monitor audit logs
 Configure HTTPS certificate
 Test rate limiting
 Test refresh-token rotation
 Test refresh-token reuse detection
 Test logout-all
 Test password reset
 Test blocked/suspended accounts
 Test invalid JWT claims
 Test CORS
 Test oversized requests
 Test unsupported HTTP methods