## <u>Spring Boot JWT Auth</u>

A focused, production-lean Spring Boot 3 service that demonstrates stateless JWT authentication with access and refresh tokens. It includes:

- Access tokens (short-lived) and refresh tokens (long-lived)
- Refresh tokens stored hashed-at-rest with device identifiers
- A JWT filter that authenticates requests via the Authorization header
- Method-level authorization checks
- Integration tests showing register → login → refresh → logout → protected user actions


## <u>Table of Contents</u>
- [Features](#features)
- [How it works (high level)](#how-it-works-high-level)
- [Quick start](#quick-start)
- [Configuration and required changes (IMPORTANT)](#configuration-and-required-changes-important)
- [API reference (with curl examples)](#api-reference-with-curl-examples)
- [Architecture overview](#architecture-overview)
- [Testing](#testing)
- [Production hardening notes](#production-hardening-notes)
- [Troubleshooting](#troubleshooting)
- [License](#license)

## <u>Features</u>
- Stateless JWT security using HS256
- Refresh tokens persisted (hashed) with deviceId and user binding
- Argon2 password hashing
- JPA with Postgres
- CORS configuration integrated with SecurityFilterChain
- Clean layering: controllers → services → repositories → entities


## <u>How it works (high level)</u>
1) Register
- POST /user/register creates a new user with ROLE_USER by default.

2) Login
- POST /auth/login authenticates using username/password via Spring Security’s AuthenticationManager.
- On success, an accessToken and refreshToken are returned along with a deviceId.
- The refresh token claims contain: id (DB id of refresh token record), userId, deviceId.
- The refresh token string is stored hashed in the database (only its hash is persisted).

3) Access protected resources
- Send Authorization: Bearer <accessToken> on requests. The JwtAuthFilter validates the token and populates the SecurityContext if valid.
- Method-level @PreAuthorize checks enforce object-level authorization in controllers.

4) Refresh
- POST /auth/refresh validates the refresh token + user/device bindings, and returns a new accessToken.

5) Logout
- POST /auth/logout invalidates the refresh token in storage (deletes the DB record). Access tokens are not persisted, so they naturally expire according to configuration.

Token contents
- Access token carries username as subject and claims: userId and roles (e.g. ["ROLE_USER"]).
- Refresh token carries a unique id (its primary key), the userId, and a random deviceId to bind the token to a logical device/session.


## <u>Quick start</u>
Prerequisites
- Java 17+
- Maven 3.9+
- Postgres running locally

Create a database
- Database name: SpringBootJwtAuth
- Example via psql:
  CREATE DATABASE "SpringBootJwtAuth";

Default connection (you can change these in application.properties):
- URL: jdbc:postgresql://localhost:5432/SpringBootJwtAuth
- Username: postgres
- Password: postgres

Run the app
- mvn spring-boot:run
- The API will be available at http://localhost:8080/api

Build
- mvn clean package


## <u>Configuration and required changes (IMPORTANT)</u>
These defaults are in src/main/resources/application.properties. Review and change them before using this beyond local development.

- spring-boot-jwt-auth.security.jwt.secret-key
  - MUST change for any non-local usage. This is your HS256 signing key. Do not commit real secrets to VCS.
  - Generate a strong key (32+ random bytes base64):
    openssl rand -base64 32

- cors.allowed-origins
  - Default: http://localhost:3000
  - Change to match your client origins. Multiple origins supported via comma-separated values if you enhance configuration handling.

- Database connection
  - Defaults:
    - spring-boot-jwt-auth.database.url=jdbc:postgresql://localhost:5432/SpringBootJwtAuth
    - spring-boot-jwt-auth.database.username=postgres
    - spring-boot-jwt-auth.database.password=postgres
  - Ensure Postgres is running and credentials match, or update these values.

Additional critical warnings
- Do not log credentials or tokens
  - JwtAuthFilter.java and LogMethodAspect.java can log Authorization headers, tokens, passwords, and other sensitive data at the debug level. Consider removing the logging or refactoring these classes if you plan to work with sensitive production data.
- Externalize secrets for public repos/CI
  - Move secrets (DB password, JWT key) to environment variables or a secure vault. Do not commit real secrets.
- Context path
  - All endpoints are prefixed with /api per server.servlet.context-path=/api. Adjust your client accordingly.
- Authorization rules
  - SecurityConfig permits "/auth/**" and "/user/**" at the HTTP layer but relies on @PreAuthorize in UserController for object-level checks. For stricter setups, require authentication at the HTTP layer for "/user/**".
- Token revocation scope
  - Access tokens are not blacklisted. If an access token is compromised, it remains valid until it expires. For higher assurance, implement a whitelist or blacklist for access tokens.
- DDL auto-update
  - spring.jpa.hibernate.ddl-auto=update is convenient locally but not recommended for production. Prefer Flyway or Liquibase migrations.
- HTTPS
  - Use HTTPS in production to protect tokens in transit.
- Browser clients
  - If building a browser-based client, avoid exposing refresh tokens to JavaScript. Consider storing refresh tokens in HttpOnly cookies and adapting the refresh flow accordingly.


## <u>API Reference (with curl examples)</u>
**Base URL:** `http://localhost:8080/api`

### 1) Register User
**Endpoint:** `POST /user/register`  
**Body:**
```json
{
  "username": "user",
  "email": "user@user.com",
  "password": "password"
}
```
**Example:**
```bash
curl -X POST http://localhost:8080/api/user/register \
  -H "Content-Type: application/json" \
  -d '{"username":"user","email":"user@user.com","password":"password"}'
```

### 2) Login
**Endpoint:** `POST /auth/login`  
**Body:**
```json
{
  "username": "user",
  "password": "password"
}
```
**Example:**
```bash
curl -X POST http://localhost:8080/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"user","password":"password"}'
```
**Response:**
```json
{
  "accessToken": "...",
  "refreshToken": "...",
  "deviceId": "..."
}
```

### 3) Get Current User (by ID)
**Endpoint:** `GET /user?userId={id}`  
**Headers:** `Authorization: Bearer <accessToken>`  
**Example:**
```bash
curl -X GET "http://localhost:8080/api/user?userId=1" \
  -H "Authorization: Bearer $ACCESS_TOKEN"
```

### 4) Update User
**Endpoint:** `PUT /user`  
**Headers:** `Authorization: Bearer <accessToken>`  
**Body:**
```json
{
  "id": 1,
  "username": "user",
  "email": "user@user.com"
}
```
**Example:**
```bash
curl -X PUT http://localhost:8080/api/user \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"id":1,"username":"user","email":"user@user.com"}'
```

### 5) Logout
**Endpoint:** `POST /auth/logout`  
**Headers:** `Authorization: Bearer <accessToken>`  
**Body:**
```json
{
  "refreshToken": "...",
  "username": "user",
  "deviceId": "..."
}
```
**Example:**
```bash
curl -X POST http://localhost:8080/api/auth/logout \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d "{\"refreshToken\":\"$REFRESH_TOKEN\",\"username\":\"user\",\"deviceId\":\"$DEVICE_ID\"}"
```

### 6) Refresh Access Token
**Endpoint:** `POST /auth/refresh`  
**Body:**
```json
{
  "refreshToken": "...",
  "username": "user",
  "deviceId": "..."
}
```
**Example:**
```bash
curl -X POST http://localhost:8080/api/auth/refresh \
  -H "Content-Type: application/json" \
  -d "{\"refreshToken\":\"$REFRESH_TOKEN\",\"username\":\"user\",\"deviceId\":\"$DEVICE_ID\"}"
```
**Response:**
```json
{
  "accessToken": "..."
}
```



## <u>Architecture overview</u>
Key classes (package org.foam.springbootjwtauth)
- config.SecurityConfig: Configures stateless security, CORS, and installs JwtAuthFilter.
- config.filter.JwtAuthFilter: Reads the Authorization header, validates access tokens, builds SecurityContext.
- service.auth.JwtService: Creates and validates JWTs; manages refresh token hashing and invalidation.
- service.auth.AuthService: Login, refresh, and logout flows.
- service.auth.UserService: Registration, CRUD, and UserDetailsService implementation.
- model.database.auth.User, Authority, RefreshToken: Entities for users, roles, and refresh tokens.
- controller.AuthController, UserController: REST endpoints for auth and user operations.
- repository.*: JPA repositories.

Entities
- users: id, username, password (Argon2 hash), email, flags, authorities
- authorities: composite key (username, authority) like ROLE_USER / ROLE_ADMIN
- refresh_token: id, token (hash), user_id, device_id


## <u>Testing</u>
- Integration tests are under src/test/java/... and expect a local Postgres according to application.properties.
- Run tests: mvn test

## <u>Production hardening notes</u>
- Replace plaintext properties with environment variables or a secrets manager.
- Change JWT secret and rotate periodically; consider key identifiers (kid) if adding rotation.
- Remove any logging of Authorization headers and tokens.
- Use Flyway/Liquibase instead of ddl-auto=update.
- Consider a blacklist/whitelist or short access token TTL plus sliding refresh for better compromise windows.
- Add validation annotations to request DTOs (@NotBlank, @Email, @Size) and @Valid on controller methods.
- If you need browser-based security, consider HttpOnly cookies for refresh tokens.
- Configure precise CORS rules; avoid '*'.


## <u>Troubleshooting</u>
- 401 Unauthorized on /auth/login: Check credentials and ensure the user exists.
- 401/403 on /user endpoints: Ensure you send Authorization: Bearer <accessToken> and that the PreAuthorize rules align with your roles (ROLE_ADMIN vs hasRole('ADMIN')).
- DB connection failures: Verify spring-boot-jwt-auth.database.* properties and that Postgres is reachable.
- JWT signature invalid: Your JWT secret key likely changed; restart app/clients with the same configured key.
- Token expired: Use /auth/refresh with a valid refresh token to get a new access token.

## <u>License</u>
This project is licensed under the MIT License. See the LICENSE file for details.

---

If you plan to publish this repo publicly:
- Remove real secrets and provide application-example.properties with placeholders.
- Document environment variables in your README (this file) or a .env.example.

