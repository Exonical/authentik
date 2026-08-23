import { aki } from "#common/api/client";

import { RotateSecretProps } from "#elements/buttons/IconRotateSecretButton";

import { ProvidersApi } from "@goauthentik/api";

import { msg } from "@lit/localize";
import { html } from "lit";

export function clientSecretRotation(pk: number): RotateSecretProps {
    return {
        onConfirm: () => aki(ProvidersApi).providersOauth2RotateSecretCreate({ id: pk }),
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
        buttonLabel: msg("Rotate client secret", {
            id: "providers.oauth2.client-secret.rotate-button.label",
        }),
    };
}
