# meSync

"I want to sync my messages across all my devices."

"I can do that for you. Call me **meSync**."

**SYNC MESsages for ME**

---

☁️ Cloud          ✅
🏗 Infrastructure ✅
🤖 Android        🚧
🖥 Desktop        🚧
🌐 Web            🚧

---

🟢 **meSync Cloud**

Spring Boot backend for secure end-to-end encrypted message synchronization.

🟢 **meSync Infrastructure**

Local development environment based on Docker Compose, PostgreSQL, Redis and Keycloak.

🚧 **meSync Android** *(planned)*

Android client for secure multi-device synchronization.

🚧 **meSync Desktop** *(planned)*

Desktop client for secure multi-device synchronization.

🚧 **meSync Web** *(planned)*

Web client for secure access to synchronized messages.

---



# meSync Cloud

meSync Cloud is a Spring Boot backend for end-to-end encrypted message
synchronization between a user's devices.

The service does not store private keys and does not decrypt user data. It
validates JWT access tokens, verifies device signatures, stores device public
keys, manages one-time device invites, accepts encrypted message records, and lets
other trusted devices sync those records.

## Features

- OAuth2/JWT resource server integration.
- Device type detection from the JWT `azp` client id.
- First-device registration limited to `MOBILE`.
- One-time invite tokens for additional `BROWSER` and `DESKTOP` devices.
- Ed25519 public key validation and signed request verification.
- Redis-backed nonce replay protection, rate limiting, invite TTL, and invite cooldown.
- PostgreSQL persistence for users, devices, and encrypted message records.
- Message synchronization API for publishing and syncing encrypted message payloads between devices.
- ProblemDetail error responses.
- Unit, repository, HTTP integration, Redis, PostgreSQL, and Keycloak tests.

## Tech Stack

- Java 17
- Spring Boot 3
- Spring Security OAuth2 Resource Server
- Spring Data JPA
- PostgreSQL
- Redis
- Flyway
- Caffeine
- Springdoc / Swagger UI
- JUnit 5
- Mockito
- Testcontainers

## Architecture

### Main Components

- `DeviceController` exposes device registration and invite endpoints.
- `MessagingController` exposes encrypted message publish and sync endpoints.
- `DeviceRegistrationService` implements onboarding rules for first and additional devices.
- `MessagingService` stores encrypted message records and reads sync batches.
- `SecurityService` extracts JWT data, runs Redis security checks, loads device auth data, and verifies signatures.
- `InvitationService` stores and consumes one-time invites in Redis.
- `DeviceService` loads cached device auth data and persists devices with name-conflict retry.
- `UserService` creates or updates local users from JWT identity data.
- `MessageEventListener` publishes post-commit sync notifications through `DeviceNotificationService`.

### Storage

PostgreSQL tables:

- `users`
- `devices`
- `messages`

Redis keys:

- registration nonce keys, scoped by user and nonce
- device-auth nonce keys, scoped by device and nonce
- registration rate-limit keys
- device-auth rate-limit keys
- invite token keys
- invite cooldown keys
- revoked device keys

## Security Model

The API uses two layers of authorization:

1. Bearer JWT authentication and role/authority checks.
2. Ed25519 signatures over canonical request payloads.

JWT data used by the service:

- `sub`: user auth id, must be a UUID
- `azp`: OAuth client id, mapped to a device type
- `email`: stored only when verified
- `email_verified`: controls whether email is trusted
- `realm_access.roles`: converted to Spring authorities

Known device client ids:

- `mesync-mobile` -> `MOBILE`
- `mesync-browser` -> `BROWSER`
- `mesync-desktop` -> `DESKTOP`
- `mesync-device-manager` -> `MANAGER`

Device-authenticated requests include:

- `devicePublicId`: registered device public id
- `nonce`: request UUID used for replay protection
- `base64Signature`: Ed25519 signature over the canonical payload

Redis rejects reused nonce keys within `nonce-ttl` and limits request volume
within `rate-limit-ttl`.

## Signed Payload Contract

All signed payloads are UTF-8 strings built by joining lines with `\n`.
The first line is always the payload version:

```text
v1
```

The signature is Ed25519 over the exact UTF-8 bytes of the payload.

### Registration

```text
v1
REGISTRATION
{inviteToken or empty string}
{base64PublicKey}
{nonce}
```

### Invite Creation

```text
v1
INVITATION
{devicePublicId}
{inviteToken}
{encryptedMasterKey}
{keyVersion}
{nonce}
```

### Message Publish

```text
v1
MESSAGE_PUBLISH
{devicePublicId}
{messagePublicId}
{address}
{messageType}
{direction}
{occurredAt}
{keyVersion}
{base64Ciphertext}
{nonce}
```

### Message Sync

```text
v1
MESSAGE_SYNC
{devicePublicId}
{lastMessageId}
{limit}
{nonce}
```

## Device Flow

### First Device Registration

1. The client obtains a JWT from the identity provider.
2. The service reads `sub`, `azp`, `email`, and `email_verified`.
3. The device type is inferred from `azp`.
4. If the user has no active devices, only `MOBILE` is allowed.
5. The service validates the provided Ed25519 public key.
6. The service verifies the signed registration payload.
7. The user and device are stored in PostgreSQL.
8. The response contains `encryptedMasterKey = null`; the first device owns initial key creation.

### Additional Device Connection

1. A trusted device calls `POST /api/v1/devices/invite`.
2. The request is authenticated by JWT, device public id, nonce, and signature.
3. The service stores `inviteToken`, `encryptedMasterKey`, `keyVersion`, and target `deviceType` in Redis.
4. The new device calls `POST /api/v1/devices/register` with the invite token.
5. The invite is consumed with get-and-delete semantics.
6. The invite device type must match the JWT client device type.
7. The response returns the encrypted master key and key version to the new device.

## API

OpenAPI is available after startup:

- `http://localhost:8081/swagger-ui.html`
- `http://localhost:8081/v3/api-docs`

### `POST /api/v1/devices/register`

Authority: `messages.read`

Registers a device. `deviceType` is not accepted from the body; it is derived
from the JWT `azp` claim.

Request:

```json
{
  "deviceName": "Pixel 8",
  "base64PublicKey": "MCowBQYDK2VwAyEA...",
  "extras": {
    "platform": "android"
  },
  "inviteToken": "123e4567-e89b-12d3-a456-426614174000",
  "nonce": "7a01801f-95cb-4dc8-9461-dbd5ec9b7fbb",
  "base64Signature": "MEUCIQ..."
}
```

For first-device registration, `inviteToken` is omitted or `null`.

Response:

```json
{
  "devicePublicId": "8f2dbf8b-7bf6-4ff9-b0d1-88beef7cd0ee",
  "deviceName": "Pixel 8",
  "encryptedMasterKey": null,
  "keyVersion": 1
}
```

### `POST /api/v1/devices/invite`

Authority: `devices.invite`

Creates an invite for a new device.

Request:

```json
{
  "devicePublicId": "8f2dbf8b-7bf6-4ff9-b0d1-88beef7cd0ee",
  "inviteToken": "123e4567-e89b-12d3-a456-426614174000",
  "encryptedMasterKey": "YmFzZTY0LWVuY3J5cHRlZC1tYXN0ZXIta2V5",
  "keyVersion": 1,
  "deviceType": "DESKTOP",
  "nonce": "7a01801f-95cb-4dc8-9461-dbd5ec9b7fbb",
  "base64Signature": "MEUCIQ..."
}
```

Response:

```json
{
  "expiresAt": "2026-04-26T10:15:30Z"
}
```

### `POST /api/v1/messages/publish`

Authority: `messages.publish`

Stores one encrypted message record from a registered device so the user's other
devices can sync it later.

Request:

```json
{
  "devicePublicId": "8f2dbf8b-7bf6-4ff9-b0d1-88beef7cd0ee",
  "messagePublicId": "8f678e8c-58f7-4975-8c9e-ff2f9e82d7ef",
  "address": "+995123456789",
  "messageType": "SMS",
  "direction": "INCOMING",
  "occurredAt": "2026-04-26T10:15:30Z",
  "keyVersion": 1,
  "base64Ciphertext": "q83v...",
  "nonce": "7a01801f-95cb-4dc8-9461-dbd5ec9b7fbb",
  "base64Signature": "MEUCIQ..."
}
```

Response:

```json
{
  "messageId": "8f678e8c-58f7-4975-8c9e-ff2f9e82d7ef"
}
```

### `POST /api/v1/messages/sync`

Authority: `messages.read`

Returns encrypted message records for the authenticated user, excluding records
published by the requesting device. The server caps the batch size to 20 records.

Request:

```json
{
  "devicePublicId": "8f2dbf8b-7bf6-4ff9-b0d1-88beef7cd0ee",
  "lastMessageId": 0,
  "limit": 20,
  "nonce": "7a01801f-95cb-4dc8-9461-dbd5ec9b7fbb",
  "base64Signature": "MEUCIQ..."
}
```

Response:

```json
{
  "messages": [
    {
      "id": 42,
      "messagePublicId": "8f678e8c-58f7-4975-8c9e-ff2f9e82d7ef",
      "devicePublicId": "8f2dbf8b-7bf6-4ff9-b0d1-88beef7cd0ee",
      "address": "+995123456789",
      "messageType": "SMS",
      "direction": "INCOMING",
      "occurredAt": "2026-04-26T10:15:30Z",
      "keyVersion": 1,
      "ciphertext": "q83v..."
    }
  ]
}
```

`ciphertext` is serialized by Jackson from a `byte[]`, so clients should treat
it as a Base64-encoded JSON string.

## Application Settings

```yaml
app:
  registration:
    invite-ttl: 10m
    invite-cooldown: 1m
    rate-limit-ttl: 10m
    attempts: 10
    nonce-ttl: 30s
  auth:
    rate-limit-ttl: 60s
    attempts: 120
    nonce-ttl: 30s
```

Meaning:

- `registration.invite-ttl`: how long an invite token lives.
- `registration.invite-cooldown`: minimum time between invite creation attempts.
- `registration.rate-limit-ttl`: rate-limit window for registration requests.
- `registration.attempts`: max registration attempts in the window.
- `registration.nonce-ttl`: replay-protection TTL for registration nonce keys.
- `auth.rate-limit-ttl`: rate-limit window for device-authenticated requests.
- `auth.attempts`: max device-authenticated requests in the window.
- `auth.nonce-ttl`: replay-protection TTL for device-authenticated nonce keys.

## Local Run

The local dependencies are expected to be started from the separate
`mesync-infrastructure` project. That project provides a Docker Compose stack
with:

- PostgreSQL `17-alpine` on `127.0.0.1:5432`
- Keycloak `26.5.2` on `127.0.0.1:8080`
- Redis `8.4.0-alpine` on `127.0.0.1:6379`

The infrastructure stack provides:

- PostgreSQL init scripts for the application and Keycloak databases
- a custom Keycloak image/build context
- Keycloak realm import files
- Redis password `supersecret123`

Start dependencies from the `mesync-infrastructure` project:

```bash
docker compose up -d --build
```

Use environment variables that match the compose stack:

```env
SPRING_PROFILES_ACTIVE=dev
JWT_ISSUER_URI=http://localhost:8080/realms/mesync
DB_URL=jdbc:postgresql://localhost:5432/mesync
DB_USER=mesync_user
DB_PASSWORD=mesync_pass
REDIS_HOST=localhost
REDIS_PORT=6379
REDIS_PASSWORD=supersecret123
```

If the imported Keycloak realm has another name, for example `mesync-test`,
set `JWT_ISSUER_URI` to that realm:

```env
JWT_ISSUER_URI=http://localhost:8080/realms/mesync-test
```

Start the application:

```bash
./gradlew bootRun
```

or:

```bash
SPRING_PROFILES_ACTIVE=dev ./gradlew bootRun
```

Run tests:

```bash
./gradlew test
```

Integration tests use Testcontainers, so Docker must be available locally.

## Test Strategy

The project contains:

- unit tests for crypto, JWT extraction, security flow, and service logic
- repository tests for JPA and SQL behavior
- MockMvc tests for HTTP endpoints
- Redis integration tests for nonce, rate limit, and get-and-delete behavior
- PostgreSQL Testcontainers integration
- Keycloak Testcontainers integration

This keeps the core E2EE-adjacent rules testable without relying on a running
local identity provider for most tests.

## Current Limitations

- Push notifications are not implemented yet; `DeviceNotificationService` is currently a placeholder.
- Device revoke and master-key rotation are planned but not implemented.
- Only `SMS` message type is currently implemented; `MMS` is planned.
