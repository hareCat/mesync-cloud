# meSync

> "I want to sync my messages across all my devices."
>
> "I can do that for you.
> I can help keep your life in sync."

**SYNC MESsages for ME**

---

☁️ Cloud          ✅
🏗 Infrastructure ✅
🤖 Android        🚧
🖥 Desktop        🚧
🌐 Web            🚧


**One ecosystem.
Many devices.
One meSync.**

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
keys, manages one-time device invites, revokes trusted devices, accepts encrypted
message records, and lets other trusted devices sync those records.

## Features

- OAuth2/JWT resource server integration.
- Device type detection from the JWT `azp` client id.
- First-device registration limited to `MOBILE`.
- One-time invite tokens for additional `BROWSER` and `DESKTOP` devices.
- Device revocation with Redis-backed revoked-device checks.
- Ed25519 public key validation and signed request verification.
- Redis-backed nonce replay protection, rate limiting, invite TTL, and invite cooldown.
- Caffeine-backed user/device authentication context caching.
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

- `DeviceRegistrationController` exposes first-device and invited-device registration endpoints.
- `DeviceController` exposes device listing and revocation endpoints.
- `MessagingController` exposes encrypted message publish and sync endpoints.
- `DeviceRegistrationService` implements onboarding rules for first and additional devices.
- `DeviceQueryService` lists the user's other devices for a trusted device.
- `DeviceRevocationService` revokes trusted devices and can advance the user's master-key version.
- `MessagingService` stores encrypted message records and reads sync batches.
- `AuthPipelineService` extracts JWT data, runs Redis security checks, verifies device ownership/type, and checks signatures.
- `AuthContextService` loads user/device auth data from Caffeine or PostgreSQL.
- `InvitationService` stores invite state, invited-device public keys, encrypted master keys, and final registration locks in Redis.
- `DeviceService` persists devices with name-conflict retry.
- `UserService` creates or updates local users from JWT identity data.
- `MessageEventListener` publishes post-commit sync notifications through `DeviceNotificationService`.
- `DeviceEventListener` caches revoked-device markers in Redis after transaction commit.

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
- invite token keys, scoped by user auth id and invite token
- invite cooldown keys
- invited-device public-key cooldown keys
- invite master-key cooldown keys
- final invite registration lock keys
- revoked device keys

Caffeine caches:

- user auth data, keyed by user auth id
- device auth data, keyed by device public id

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

The API must receive a Keycloak `access_token`, not an `id_token`. The access
token must contain `typ=Bearer`, `sub`, `azp`, and `realm_access.roles`. In
Keycloak, device clients must not use lightweight access tokens if that removes
`sub` from the token. The local realm also attaches the `basic` client scope to
device clients so the built-in `sub` mapper is included in access tokens.

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
{deviceName}
{nonce}
```

### Invite Creation

```text
v1
INVITATION_STORE_INVITE
{devicePublicId}
{inviteToken}
{deviceType}
{keyVersion}
{nonce}
```

### Invited Device Public Keys

```text
v1
INVITATION_STORE_PUBLIC_KEYS
{inviteToken}
{base64EncryptionPublicKey}
{base64SigningPublicKey}
{nonce}
```

### Invite Master Key

```text
v1
INVITATION_STORE_MASTER_KEY
{devicePublicId}
{inviteToken}
{base64EncryptedMasterKey}
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

### Device List

```text
v1
DEVICE_LIST
{devicePublicId}
{nonce}
```

### Device Revocation

```text
v1
REVOCATION
{devicePublicId}
{targetDevicePublicId}
{deviceMasterKeyVersion}
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

1. A trusted device calls `POST /api/v1/register/invite`.
2. The request is authenticated by JWT, device public id, nonce, and signature.
3. The service stores `inviteToken` and target `deviceType` in Redis.
4. The invited device calls `POST /api/v1/register/public-key` with its encryption and signing public keys.
5. The public-key request is signed by the invited signing key as proof of possession.
6. The trusted device reads the invited encryption public key on the client side, encrypts the master key, and calls `POST /api/v1/register/master-key`.
7. The service stores `base64EncryptedMasterKey` and `keyVersion` only after public keys are present in the invite.
8. The invited device calls `POST /api/v1/register` with the invite token.
9. The invite device type and signing public key must match the JWT client device type and registration public key.
10. The service locks the final invite step, saves the device, deletes the invite, and returns the encrypted master key and key version to the new device.

### Device Revocation

1. A trusted device calls `POST /api/v1/devices/revoke`.
2. The request is authenticated by JWT, device public id, nonce, and signature.
3. The target device must belong to the same user and must not already be revoked.
4. The service marks the target device as revoked in PostgreSQL.
5. The target device auth cache entry is invalidated.
6. After commit, Redis stores a revoked-device marker used by device-authenticated requests.
7. If requested, the user's master-key version is advanced by exactly one version.

### Device List

1. A trusted device calls `POST /api/v1/devices/list`.
2. The request is authenticated by JWT, device public id, nonce, and signature.
3. The service returns the user's other devices and excludes the requesting device.

## API

OpenAPI is available after startup:

- `http://localhost:8081/swagger-ui.html`
- `http://localhost:8081/v3/api-docs`

### `POST /api/v1/register`

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
  "inviteToken": "A1B2C3",
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

For additional-device registration, the response contains `encryptedMasterKey`
and `keyVersion` from the invite.

### `POST /api/v1/register/invite`

Authority: `devices.invite`

Creates an invite for a new device. This step stores only the invite token and
the target device type. The encrypted master key is stored later through
`POST /api/v1/register/master-key`.

Request:

```json
{
  "devicePublicId": "8f2dbf8b-7bf6-4ff9-b0d1-88beef7cd0ee",
  "inviteToken": "A1B2C3",
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

### `POST /api/v1/register/public-key`

Authority: `messages.read`

Stores the invited device encryption public key and signing public key in the
Redis invite. The request signature is verified with `base64SigningPublicKey`,
which proves the invited device controls the private signing key before the
device is registered.

Request:

```json
{
  "inviteToken": "A1B2C3",
  "base64EncryptionPublicKey": "MCowBQYDK2VwAyEA...",
  "base64SigningPublicKey": "MCowBQYDK2VwAyEA...",
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

### `POST /api/v1/register/master-key`

Authority: `devices.invite`

Stores the master key encrypted for the invited device. The invite must already
contain public keys from `POST /api/v1/register/public-key`.

Request:

```json
{
  "devicePublicId": "8f2dbf8b-7bf6-4ff9-b0d1-88beef7cd0ee",
  "inviteToken": "A1B2C3",
  "base64EncryptedMasterKey": "YmFzZTY0LWVuY3J5cHRlZC1tYXN0ZXIta2V5",
  "keyVersion": 1,
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

### `POST /api/v1/devices/list`

Authority: `messages.read`

Returns the authenticated user's other devices, excluding the requesting device.
The response includes active and revoked devices so clients can reconcile local
device state.

Request:

```json
{
  "devicePublicId": "8f2dbf8b-7bf6-4ff9-b0d1-88beef7cd0ee",
  "nonce": "7a01801f-95cb-4dc8-9461-dbd5ec9b7fbb",
  "base64Signature": "MEUCIQ..."
}
```

Response:

```json
{
  "devices": [
    {
      "devicePublicId": "fddbe426-f388-4dbb-8efb-72b313ac47b0",
      "deviceType": "DESKTOP",
      "name": "Work laptop",
      "createdAt": "2026-04-26T10:15:30Z",
      "revokedAt": null,
      "lastActiveAt": "2026-04-26T10:20:30Z"
    }
  ]
}
```

### `POST /api/v1/devices/revoke`

Authority: `devices.revoke`

Revokes one of the user's devices. The request is signed by a currently trusted
device. When `rotateMasterKey` is true, `deviceMasterKeyVersion` must be exactly
one greater than the user's stored key version.

Request:

```json
{
  "devicePublicId": "8f2dbf8b-7bf6-4ff9-b0d1-88beef7cd0ee",
  "targetDevicePublicId": "fddbe426-f388-4dbb-8efb-72b313ac47b0",
  "rotateMasterKey": true,
  "deviceMasterKeyVersion": 2,
  "nonce": "7a01801f-95cb-4dc8-9461-dbd5ec9b7fbb",
  "base64Signature": "MEUCIQ..."
}
```

Response:

```json
{
  "revokedDevicePublicId": "fddbe426-f388-4dbb-8efb-72b313ac47b0",
  "revokedAt": "2026-04-26T10:15:30Z"
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
    invite-cooldown: 10s
    nonce-ttl: 30s
    rate-limit-ttl: 10m
    attempts: 10
  auth:
    nonce-ttl: 30s
    rate-limit-ttl: 60s
    attempts: 120
  revoke:
    ttl: 30d
  cache:
    ttl: 12h
    user-cache-size: 40_000
    device-cache-size: 100_000
```

Meaning:

- `registration.invite-ttl`: how long an invite token lives.
- `registration.invite-cooldown`: minimum time between invite flow state-changing steps.
- `registration.rate-limit-ttl`: rate-limit window for registration requests.
- `registration.attempts`: max registration attempts in the window.
- `registration.nonce-ttl`: replay-protection TTL for registration nonce keys.
- `auth.rate-limit-ttl`: rate-limit window for device-authenticated requests.
- `auth.attempts`: max device-authenticated requests in the window.
- `auth.nonce-ttl`: replay-protection TTL for device-authenticated nonce keys.
- `revoke.ttl`: how long Redis keeps revoked-device markers.
- `cache.ttl`: Caffeine auth-context cache expiration after access.
- `cache.user-cache-size`: max cached user auth contexts.
- `cache.device-cache-size`: max cached device auth contexts.

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

The local Keycloak realm must issue application-compatible access tokens for
device clients:

- use `access_token` in `Authorization: Bearer`, not `id_token`
- `typ` must be `Bearer`
- `sub` must be present and must be a UUID
- `azp` must be one of the known device client ids
- `realm_access.roles` must include the endpoint authority
- lightweight access tokens must be disabled for `mesync-mobile`,
  `mesync-browser`, `mesync-desktop`, and `mesync-device-manager`
- the `basic` client scope must be attached to those clients so the `sub`
  mapper is included in access tokens

Start the application:

```bash
./gradlew bootRun
```

or:

```bash
SPRING_PROFILES_ACTIVE=dev ./gradlew bootRun
```

## Postman

A local Postman collection is available at:

- `postman/mesync-cloud.postman_collection.json`

The collection uses:

- `baseUrl=http://localhost:8081`
- `keycloakUrl=http://localhost:8080`
- `jwt` as the bearer token variable

Run `Auth / Get Token` first. It requests a Keycloak password-grant
`access_token` for `mesync-mobile` and stores it into the collection variable
`jwt`.

The request bodies contain valid Ed25519 public keys and signatures for the
static example payloads in the collection. Signatures are tied to the exact
canonical payload. If a signed field changes, for example `nonce`,
`devicePublicId`, `inviteToken`, `messagePublicId`, or `base64Ciphertext`, the
`base64Signature` must be regenerated.

For first-device registration, `Register Device` uses `inviteToken: null`.
After registration, copy the returned `devicePublicId` into the device-auth
requests and regenerate signatures for the changed payloads.

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
- Redis/invite-flow tests for nonce, rate limit, invite TTL, and final invite locking behavior
- Caffeine auth-context cache unit tests
- PostgreSQL Testcontainers integration
- Keycloak Testcontainers integration
- Keycloak token-contract checks for `sub`, `azp`, `typ`, issuer, email claims, and realm roles

This keeps the core E2EE-adjacent rules testable without relying on a running
local identity provider for most tests.

## Current Limitations

- Push notifications are not implemented yet; `DeviceNotificationService` is currently a placeholder.
- Only `SMS` message type is currently implemented; `MMS` is planned.
