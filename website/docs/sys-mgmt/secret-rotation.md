---
title: Secret rotation
description: "Replace a secret that authentik generated with a freshly generated one."
authentik_version: "2026.11.0"
---

authentik generates the secrets it hands out: client secrets, shared secrets, and token keys. Each one comes from the same generator as every other, so you get a secret of known strength without reaching for `openssl rand` and pasting the result into a form.

Any of them can be replaced later, from the Admin interface or the API.

## What can be rotated

| Object                 | Field         | Where                                                                         |
| ---------------------- | ------------- | ----------------------------------------------------------------------------- |
| OAuth2/OpenID provider | Client secret | Edit the provider                                                             |
| RADIUS provider        | Shared secret | Edit the provider                                                             |
| Token, app password    | Key           | **Directory** > **Tokens and App passwords**, and any page that shows a token |
| Agent enrollment token | Key           | The enrollment token list                                                     |

Click the rotate icon next to the value and confirm. Rotating takes the same `change` permission on the object as editing it does, and is recorded as a [`secret_rotate`](./events/event-actions.md#secret_rotate) event. Rotating someone else's token additionally takes **Set a token's key**, the same permission as setting a key by hand; your own tokens need neither.

A client ID is generated the same way but cannot be rotated. Clients are configured with it as an identifier, so replacing it renames the client rather than re-securing it.

:::danger Rotating cannot be undone
The new secret applies the moment you confirm. Closing the form without saving does not bring the old one back.
:::

## Getting the new value

The field shows the new secret as soon as it is generated, ready to copy.

Token keys work differently. A key is never part of an API response, this one included, so that reading a key stays an audited act of its own. Use the copy button next to the token, which fetches the key and records that access.

## Automatic rotation

Rotation is not only something you click. An API token that reaches the end of its lifetime has its key replaced instead of being deleted, through the same code path, recording the same event.

## Secrets authentik does not generate

Secrets that belong to another system, such as an OAuth source's consumer secret or an LDAP bind password, are yours to set. Change those by editing the object.
