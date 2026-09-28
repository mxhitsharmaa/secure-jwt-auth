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
secu
```
