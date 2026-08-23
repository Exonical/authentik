import { aki } from "#common/api/client";

import { RotateSecretProps } from "#elements/buttons/IconRotateSecretButton";

import { ProvidersApi } from "@goauthentik/api";

import { msg } from "@lit/localize";
import { html } from "lit";

export function sharedSecretRotation(pk: number): RotateSecretProps {
    return {
        onConfirm: () => aki(ProvidersApi).providersRadiusRotateSecretCreate({ id: pk }),
        header: msg("Rotate shared secret", { id: "providers.radius.shared-secret.rotate.header" }),
        body: html`<p>
            ${msg(
                "The current shared secret stops working as soon as the outpost picks up the change, which usually takes a few seconds. Update every RADIUS client with the new secret afterwards.",
                { id: "providers.radius.shared-secret.rotate.description" },
            )}
        </p>`,
        successMessage: msg("Successfully rotated shared secret.", {
            id: "providers.radius.shared-secret.rotate.success",
        }),
        errorMessage: msg("Failed to rotate shared secret", {
            id: "providers.radius.shared-secret.rotate.error",
        }),
        buttonLabel: msg("Rotate shared secret", {
            id: "providers.radius.shared-secret.rotate-button.label",
        }),
    };
}
