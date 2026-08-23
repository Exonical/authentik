import { aki } from "#common/api/client";

import { IconRotateSecretButton } from "#elements/buttons/IconRotateSecretButton";
import { SlottedTemplateResult } from "#elements/types";

import { CoreApi, EndpointsApi } from "@goauthentik/api";

import { msg } from "@lit/localize";
import { html } from "lit";
import { guard } from "lit-html/directives/guard.js";

/**
 * Rotates a token's key. Pair with a copy button, which hands out the new key afterwards.
 */
export function IconTokenRotateButton(
    identifier: string | null | undefined,
    rotate: () => Promise<unknown>,
): SlottedTemplateResult {
    return guard([identifier], () =>
        identifier
            ? IconRotateSecretButton({
                  rotate,
                  header: msg("Rotate token", { id: "tokens.rotate.header" }),
                  body: html`<p>
                      ${msg(
                          "The current key stops working immediately. Anything using this token has to be updated with the new key, which can be copied afterwards.",
                          { id: "tokens.rotate.description" },
                      )}
                  </p>`,
                  successMessage: msg("Successfully rotated token.", {
                      id: "tokens.rotate.success",
                  }),
                  errorMessage: msg("Failed to rotate token", { id: "tokens.rotate.error" }),
              })
            : null,
    );
}

export const IconCoreTokenRotateButton = (identifier?: string | null) =>
    IconTokenRotateButton(identifier, () =>
        aki(CoreApi).coreTokensRotateSecretCreate({ identifier: identifier! }),
    );

export const IconEnrollmentTokenRotateButton = (tokenUuid?: string | null) =>
    IconTokenRotateButton(tokenUuid, () =>
        aki(EndpointsApi).endpointsAgentsEnrollmentTokensRotateSecretCreate({
            tokenUuid: tokenUuid!,
        }),
    );
