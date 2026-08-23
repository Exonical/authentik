---
title: Secret rotation
description: "Replace a secret that authentik generated with a freshly generated one."
authentik_version: "2026.11.0"
---

authentik generates secrets for the objects that need one: client secrets, shared secrets, and token keys. Any of them can be replaced with a newly generated value, without recreating the object it belongs to.

## What can be rotated

| Object                 | Field         | Where                                                                                                    |
| ---------------------- | ------------- | -------------------------------------------------------------------------------------------------------- |
| OAuth2/OpenID provider | Client secret | Edit the provider, next to **Client Secret**                                                             |
| RADIUS provider        | Shared secret | Edit the provider, next to **Shared secret**                                                             |
| Token, app password    | Key           | **Directory** > **Tokens and App passwords**, a user's token list, and the outpost and SCIM source pages |
| Agent enrollment token | Key           | The enrollment token list of the agent connector                                                         |

Click the rotate icon next to the value, then confirm. Rotating requires the same `change` permission on the object as editing it does.

## What happens

The old value stops working, and everything using it has to be updated with the new one. Rotating applies as soon as you confirm, so closing an edit form without saving does not undo it.

Each rotation is recorded as a [`secret_rotate`](./events/event-actions.md#secret_rotate) event. The event names the object and the field, never the value.

Where the new value is readable, the field shows it and you can copy it from there. Token keys are the exception: they are only handed out through their own view-key endpoint, which needs the `view_token_key` permission and logs an access event, so a rotation returns nothing to copy. Copy the key from the list afterwards.

Rotating a secret that authentik generated does not touch secrets you supplied yourself, such as an OAuth source's consumer secret or an LDAP bind password. Change those by editing the object.

## Consequences per protocol

Rotating breaks running clients until they are updated, and how that failure looks depends on the protocol:

- [OAuth2/OpenID providers](../add-secure-apps/providers/oauth2/create-oauth2-provider.md#rotate-the-client-secret): clients authenticating with the old secret are rejected, and ID tokens signed with it no longer validate when the provider has no signing key.
- [RADIUS providers](../add-secure-apps/providers/radius/index.mdx#shared-secret): the outpost picks up the new secret within a few seconds, and clients still using the old one are rejected.
- Outpost tokens: the outpost is redeployed with the new key. A manually deployed outpost has to be updated with it.

## Generated values

Leave a generated field empty when creating an object and authentik fills it in, in the Admin interface and the API alike. The value comes from the model default, so it is the same whether the object is created through the Admin interface, the API, or a blueprint.
