## Arika Auth

`@arikajs/auth` provides a flexible authentication system for the ArikaJS framework.

It enables applications to authenticate users using session-based (web) or token-based (API) guards, while remaining lightweight, extensible, and framework-agnostic.

```ts
import { AuthManager } from '@arikajs/auth';

if (await auth.attempt({ email, password })) {
  const user = auth.user();
}
```

---

### Status

- **Stage**: Experimental / v0.x
- **Scope (v0.x)**:
  - Multi-guard authentication (Session & Token)
  - User Provider interface
  - Password hashing
  - Middleware integration
  - JS & TS friendly API
- **Out of scope (for this package)**:
  - OAuth logic
  - Database ORM implementation
  - Authorization (Policies/Gates)

---

## 🎯 Purpose

Authentication answers one core question: **“Who is the current user?”**

This package is responsible for:
- Authenticating users
- Managing login & logout
- Maintaining authentication state
- Providing guards for different auth strategies
- Integrating with HTTP middleware and controllers

---

## 🧠 Responsibilities

### ✅ What Arika Auth Does
- Authenticate users via multiple guards
- Support session and token authentication
- Hash and verify passwords securely
- Attach authenticated user to the request
- Provide authentication middleware
- Offer a clean API for controllers and routes

### ❌ What Arika Auth Does NOT Do
- Authorization (policies / gates)
- User database or ORM management
- OAuth / social login (future scope)
- Session storage implementation (uses HTTP layer)

---

## Features

- **Multiple authentication guards**
  - Configure different strategies for API vs Web.
- **Session-based authentication**
  - Secure defaults for browser-based apps.
- **Token-based authentication**
  - Simple API token validation.
- **Pluggable user providers**
  - Connect to any database or ORM.
- **Secure password hashing**
  - Industry-standard hashing algorithms (Bcrypt/Argon2).
- **Middleware-based protection**
  - Easily secure routes.

---

## Installation

```bash
npm install @arikajs/auth
# or
yarn add @arikajs/auth
# or
pnpm add @arikajs/auth
```

---

## 🧬 Authentication Flow

```
Request
  ↓
Authenticate Middleware
  ↓
Auth Guard
  ↓
User Provider
  ↓
Authenticated User (or null)
```

---

## 🧩 Guards

Guards define how users are authenticated.

### Built-in Guards (v0.x)

| Guard | Description |
| :--- | :--- |
| `session` | Cookie/session-based authentication with "Remember Me" support |
| `jwt` | Stateless API authentication using JSON Web Tokens (JWT) |
| `token` | Header-based token authentication |
| `basic` | HTTP Basic Authentication support |

---

## 🧱 User Providers

User providers define how users are retrieved.

```ts
export interface UserProvider {
  retrieveById(id: string | number): Promise<any>;
  retrieveByToken?(id: string | number, token: string): Promise<any>;
  updateRememberToken?(user: any, token: string | null): Promise<void>;
  retrieveByCredentials(credentials: Record<string, any>): Promise<any>;
  validateCredentials(user: any, credentials: Record<string, any>): boolean | Promise<boolean>;
}
```

Providers allow you to integrate any database or user store.

---

## 🔌 Basic Usage

### Checking Authentication State

```ts
import { auth } from '@arikajs/auth';

if (auth.check()) {
  const user = auth.user();
}
```

### Attempting Login

```ts
// The second parameter `true` enables "Remember Me"
const success = await auth.attempt({
  email: 'test@example.com',
  password: 'secret',
}, true);

if (!success) {
  throw new Error('Invalid credentials');
}
```

### Logging Out

```ts
await auth.logout();
```

---

## 🔒 Middleware Protection

### Protecting Routes

```ts
Route.get('/dashboard', handler)
  .middleware(['auth']);
```

### API Authentication

```ts
Route.get('/api/user', handler)
  .middleware(['auth:jwt']); // or auth:token, auth:basic
```

---

## 🚀 Advanced Features

### Stateless JWT Authentication
Get high-performance stateless API auth without querying `api_token` in your database.
```ts
const jwtString = await auth.guard('jwt').attempt({ email, password });
// Issues standard Bearer eyJhbX...
```

### "Remember Me" Capability
Keep users logged in seamlessly across browser restarts using long-lived secure cookies.
```ts
// Just pass `true` as the second argument:
await auth.attempt(credentials, true);
```

### Login Throttling (Rate Limiting)
ArikaJS Auth automatically integrates with RateLimiters to protect against brute-force attacks!
```ts
// If an IP/email hits max failed logins (e.g. 5x)
// `auth.attempt` throws Error: 'Too many login attempts.'
authManager.setRateLimiter(new RedisRateLimiter());
```

### Event Dispatching
ArikaJS fires core auth events so you can hook into the lifecycle without modifying your controllers (e.g. for logging or email alerts):
- `Auth.Attempting`
- `Auth.Login`
- `Auth.Failed`
- `Auth.Logout`
- `Auth.Lockout`

---

## ⚙️ Configuration

Example configuration:

```json
{
  "default": "session",
  "guards": {
    "session": {
      "driver": "session",
      "provider": "users"
    },
    "token": {
      "driver": "token",
      "provider": "users"
    }
  }
}
```

---

## 🔐 Password Hashing

```ts
import { Hasher } from '@arikajs/auth';

const hash = await Hasher.make('password');
const valid = await Hasher.check('password', hash);
```

Uses industry-standard hashing algorithms.

---

## 🧱 Project Structure

- `src/`
  - `AuthManager.ts` – Main entry point
  - `Guard.ts` – Guard interface
  - `Guards/` – Implementations
    - `SessionGuard.ts`, `TokenGuard.ts`, `JwtGuard.ts`, `BasicGuard.ts`
  - `Hasher.ts` – Password hashing utility
  - `Middleware/` – Auth middleware
    - `Authenticate.ts`
  - `Contracts/` – Interfaces
    - `UserProvider.ts`, `EventDispatcher.ts`, `RateLimiter.ts`
  - `index.ts` – Public exports
- `package.json`
- `tsconfig.json`
- `README.md`
- `LICENSE`

---

## Versioning & Stability

- Current version: **v0.x** (experimental)
- API may change before **v1.0**
- Will follow semantic versioning after stabilization

---

## 📜 License

`@arikajs/auth` is open-sourced software licensed under the **MIT License**.

---

## 🧠 Philosophy

> “Authentication identifies the user. Authorization defines their power.”
