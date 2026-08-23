import { aki } from "#common/api/client";

import { RotateSecretProps } from "#elements/buttons/IconRotateSecretButton";

import { ProvidersApi } from "@goauthentik/api";

import { msg } from "@lit/localize";
import { html } from "lit";

export const clientSecretRotation = (pk: number): RotateSecretProps => ({
    rotate: () => aki(ProvidersApi).providersOauth2RotateSecretCreate({ id: pk }),
    header: msg("Rotate client secret", { id: "providers.oauth2.client-secret.rotate.header" }),
    body: html`<p>
        ${msg(
            "The current client secret stops working immediately. Clients authenticating with it are rejected, and if this provider has no signing key, ID tokens signed with it no longer validate. Update every client with the new secret afterwards.",
            { id: "providers.oauth2.client-secret.rotate.description" },
        )}
    </p>`,
    successMessage: msg("Successfully rotated client secret.", {
        id: "providers.oauth2.client-secret.rotate.success",
    }),
    errorMessage: msg("Failed to rotate client secret", {
        id: "providers.oauth2.client-secret.rotate.error",
    }),
});

export const sharedSecretRotation = (pk: number): RotateSecretProps => ({
    rotate: () => aki(ProvidersApi).providersRadiusRotateSecretCreate({ id: pk }),
    header: msg("Rotate shared secret", { id: "providers.radius.shared-secret.rotate.header" }),
    body: html`<p>
        ${msg(
            "The current shared secret stops working as soon as the outpost picks up the change, usually within seconds. Update every RADIUS client with the new secret afterwards.",
            { id: "providers.radius.shared-secret.rotate.description" },
        )}
    </p>`,
    successMessage: msg("Successfully rotated shared secret.", {
        id: "providers.radius.shared-secret.rotate.success",
    }),
    errorMessage: msg("Failed to rotate shared secret", {
        id: "providers.radius.shared-secret.rotate.error",
    }),
});
