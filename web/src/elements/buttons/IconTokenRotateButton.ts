import { aki } from "#common/api/client";

import { IconRotateSecretButton } from "#elements/buttons/IconRotateSecretButton";
import { SlottedTemplateResult } from "#elements/types";

import { CoreApi, EndpointsApi } from "@goauthentik/api";

import { msg } from "@lit/localize";
import { nothing } from "lit";

const entityLabel = () => msg("token", { id: "tokens.rotate.entity" });

/**
 * Rotates a token's key. Pair with a copy button, which hands out the new key afterwards; the key
 * itself is never part of the rotate response.
 */
export const IconCoreTokenRotateButton = (identifier?: string | null): SlottedTemplateResult =>
    identifier
        ? IconRotateSecretButton({
              rotate: () => aki(CoreApi).coreTokensRotateSecretCreate({ identifier }),
              entityLabel: entityLabel(),
          })
        : nothing;

/** @see {@linkcode IconCoreTokenRotateButton} */
export const IconEnrollmentTokenRotateButton = (
    tokenUuid?: string | null,
): SlottedTemplateResult =>
    tokenUuid
        ? IconRotateSecretButton({
              rotate: () =>
                  aki(EndpointsApi).endpointsAgentsEnrollmentTokensRotateSecretCreate({ tokenUuid }),
              entityLabel: entityLabel(),
          })
        : nothing;
