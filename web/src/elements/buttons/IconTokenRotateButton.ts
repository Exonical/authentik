import { aki } from "#common/api/client";

import { IconRotateSecretButton } from "#elements/buttons/IconRotateSecretButton";
import { SlottedTemplateResult } from "#elements/types";

import { CoreApi, EndpointsApi } from "@goauthentik/api";

import { msg } from "@lit/localize";
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
                  entityLabel: msg("token", { id: "tokens.rotate.entity" }),
                  warning: msg(
                      "The current key stops working immediately. Anything using this token has to be updated with the new key, which can be copied afterwards.",
                      { id: "tokens.rotate.description" },
                  ),
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
