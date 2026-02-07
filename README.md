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
| `session` | Cookie/session-based authentication |
| `token` | Header-based token authentication |

---

## 🧱 User Providers

User providers define how users are retrieved.

```ts
export interface UserProvider {
  retrieveById(id: string | number): Promise<any>;
  retrieveByCredentials(credentials: object): Promise<any>;
  validateCredentials(user: any, credentials: object): boolean;
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
const success = await auth.attempt({
  email: 'test@example.com',
  password: 'secret',
});

if (!success) {
  throw new Error('Invalid credentials');
}
```

### Logging Out

```ts
auth.logout();
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
  .middleware(['auth:token']);
```

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
    - `SessionGuard.ts`, `TokenGuard.ts`
  - `Hasher.ts` – Password hashing utility
  - `Middleware/` – Auth middleware
    - `Authenticate.ts`
  - `Contracts/` – Interfaces
    - `UserProvider.ts`
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
