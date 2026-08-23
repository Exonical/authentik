import { aki } from "#common/api/client";

import { IconRotateSecretButton } from "#elements/buttons/IconRotateSecretButton";
import { SlottedTemplateResult } from "#elements/types";

import { EndpointsApi } from "@goauthentik/api";

import { msg } from "@lit/localize";
import { html } from "lit";
import { guard } from "lit-html/directives/guard.js";

/**
 * Rotates an enrollment token's key. Pair with `IconEnrollmentTokenCopyButton`.
 */
export function IconEnrollmentTokenRotateButton(tokenUuid?: string | null): SlottedTemplateResult {
    return guard([tokenUuid], () => {
        if (!tokenUuid) {
            return null;
        }

        return IconRotateSecretButton({
            onConfirm: () =>
                aki(EndpointsApi).endpointsAgentsEnrollmentTokensRotateSecretCreate({ tokenUuid }),
            header: msg("Rotate enrollment token", {
                id: "enrollment-tokens.rotate.header",
                desc: "Header of the confirmation dialog for rotating an enrollment token's key.",
            }),
            body: html`<p>
                ${msg(
                    "The current key stops working immediately. Devices that have not finished enrolling with it have to be given the new key, which can be copied once the rotation is done. Devices that are already enrolled are not affected.",
                    {
                        id: "enrollment-tokens.rotate.description",
                        desc: "Body of the confirmation dialog for rotating an enrollment token's key.",
                    },
                )}
            </p>`,
            successMessage: msg("Successfully rotated enrollment token.", {
                id: "enrollment-tokens.rotate.success",
            }),
            errorMessage: msg("Failed to rotate enrollment token", {
                id: "enrollment-tokens.rotate.error",
            }),
            buttonLabel: msg("Rotate token", {
                id: "enrollment-tokens.rotate-button.label",
                desc: "Label for a button that replaces an enrollment token's key with a newly generated one.",
            }),
        });
    });
}
