# Cloud user registry

This service keeps track of users and their access.

# Models

## User

A **User** represents a person who can login. A **User** has
* A username
* A password
* A first name
* A last name
* An e-mail

## Group

A **Group** is just something a **User** can belong to. 
Generally other resources are associated with a **Group**, and **Users** gain access to those resources by being part of the **Group** that owns it. A **User** can belong to multiple **Groups**, but only actively interact with one group at a time, but can actively switch between them whenever.

## Group-User link

Links a **Group** with **User** and has boolean fields for different roles of that **Group**. Eg
* *admin*
* *owner* (*admin* powers, not alterable by other *admins*)

# Functionality

## Registration

You should be able to register a new user where you simply need to provide the information required to create a **User**. When doing this, a **Group** is created automatically for you where you are the administrator.

## Invitation

If you are an *administrator* of a **Group**, you should be able to invite other **Users** to the **Group**

# Architecture

* Data stored in MariaDB
* JWT provided after authentication contains userId (primary key of **Users**) and groupID (Primary key of **Groups**)
* This service owns that token format and exports it as the public Go package `github.com/Kaese72/cloud-user-registry/cloudtoken` (part of this module, not a separate one). Go services that need to authenticate cloud callers import it instead of re-implementing the format:
  * `cloudtoken.FromAuthHeader(publicKey, header)` / `cloudtoken.Verify(publicKey, token)` verify a `use` token and return the user ID and group ID. A token without a valid `id` and `groupId` is rejected, and so is the HS256 refresh token.
  * `cloudtoken.Middleware(publicKey, skipPrefixes...)` requires a valid `use` token on every request and makes the caller available to handlers via `cloudtoken.UserID(ctx)` and `cloudtoken.GroupID(ctx)`.
  * `cloudtoken.LoadPublicKeyFromFile(path)` / `cloudtoken.ParsePublicKey(pem)` load this service's PKIX PEM-encoded RSA public key.
  * `cloudtoken.Sign` issues a `use` token; only this service, which holds the private key, should call it.
  * This is *not* the authentication service's `use` token (`authentication/usertoken`): that one is issued per appliance, has no group, and is signed with a different key. The refresh token stays private to this service (`internal/tokens`).
  * The package depends only on the JWT library and `huemie-lib`, so importing it does not pull this service's own dependencies (database driver, SMTP, ...) into the importing service.
* Link table between **Users** and **Groups**, containing the role of the user (*admin*=`true` or not)
* Only *admins* can add or remove the *admin* flag on links to **Users** of **Groups** they are *admin* over
* When a new **Group** is created, the creator (generally via registration) becomes *owner* (tracked in link table) and this can not be changed, even by *admins*

