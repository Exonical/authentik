import { aki } from "#common/api/client";

import { IconRotateSecretButton } from "#elements/buttons/IconRotateSecretButton";
import { SlottedTemplateResult } from "#elements/types";

import { CoreApi } from "@goauthentik/api";

import { msg } from "@lit/localize";
import { html } from "lit";
import { guard } from "lit-html/directives/guard.js";

/**
 * Rotates a token's key. Pair with `IconTokenCopyButton`, which hands out the new key afterwards.
 */
export function IconTokenRotateButton(identifier?: string | null): SlottedTemplateResult {
    return guard([identifier], () => {
        if (!identifier) {
            return null;
        }

        return IconRotateSecretButton({
            onConfirm: () => aki(CoreApi).coreTokensRotateSecretCreate({ identifier }),
            header: msg("Rotate token", {
                id: "tokens.rotate.header",
                desc: "Header of the confirmation dialog for rotating a token's key.",
            }),
            body: html`<p>
                ${msg(
                    "The current key stops working immediately. Anything that authenticates with this token has to be updated with the new key, which can be copied once the rotation is done.",
                    {
                        id: "tokens.rotate.description",
                        desc: "Body of the confirmation dialog for rotating a token's key.",
                    },
                )}
            </p>`,
            successMessage: msg("Successfully rotated token.", { id: "tokens.rotate.success" }),
            errorMessage: msg("Failed to rotate token", { id: "tokens.rotate.error" }),
            buttonLabel: msg("Rotate token", {
                id: "tokens.rotate-button.label",
                desc: "Label for a button that replaces a token's key with a newly generated one.",
            }),
        });
    });
}
