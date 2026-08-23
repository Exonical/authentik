import "#elements/dialogs/ak-modal";
import "@patternfly/elements/pf-tooltip/pf-tooltip.js";

import { aki } from "#common/api/client";
import { AKRefreshEvent } from "#common/events";
import { MessageLevel } from "#common/messages";

import { renderConfirmation } from "#elements/dialogs/utils";
import { showAPIErrorMessage, showMessage } from "#elements/messages/MessageContainer";
import { SlottedTemplateResult } from "#elements/types";

import { CoreApi, RotatedSecret } from "@goauthentik/api";

import { msg } from "@lit/localize";
import { html, nothing } from "lit";

export interface RotateSecretProps {
    /** Calls the rotate endpoint. */
    rotate: () => Promise<RotatedSecret>;
    /** Hands the new secret to the field that owns it, instead of reloading the page around it. */
    apply?: (secret: string) => void;
    /** Render as a bordered input-group control, for use next to an input. */
    control?: boolean;
}

/**
 * An icon button that replaces a secret with a newly generated one, after confirmation. The
 * confirmation opens in the top layer, so it also works inside a form modal.
 *
 * Prefer the `rotate` property of {@linkcode AkHiddenTextInput}; this is for secrets with no field
 * of their own to sit next to, such as a table cell.
 */
export function IconRotateSecretButton({
    rotate,
    apply,
    control = false,
}: RotateSecretProps): SlottedTemplateResult {
    const headline = msg("Rotate secret", { id: "secret-rotate.confirm.header" });

    const open = async (event: Event) => {
        // Read the invoker before any await: event targets inside a shadow tree are cleared once
        // dispatch finishes.
        const invoker = event.currentTarget as HTMLElement;

        let secret: string | null | undefined;

        const confirmed = await renderConfirmation(
            html`<p>
                    ${msg("Everything using the old value has to be updated with the new one.", {
                        id: "secret-rotate.confirm.warning",
                    })}
                </p>
                ${invoker.closest("form")
                    ? html`<p>
                          ${msg("Rotating applies immediately, even if you don't save this form.", {
                              id: "secret-rotate.confirm.unsaved",
                          })}
                      </p>`
                    : nothing}`,
            async () => {
                try {
                    secret = (await rotate()).secret;
                } catch (error) {
                    await showAPIErrorMessage(error);

                    throw error;
                }
            },
            {
                headline,
                action: msg("Rotate", { id: "secret-rotate.confirm.action" }),
                invokerElement: invoker,
            },
        );

        if (!confirmed) return;

        // The field takes the new value directly, so it is right even before the refresh lands.
        if (secret && apply) apply(secret);

        // Anything else showing the old secret, such as the page behind this form, would go on
        // offering it for copying.
        invoker.dispatchEvent(new AKRefreshEvent());

        showMessage({
            message: msg("Successfully rotated secret.", { id: "secret-rotate.success" }),
            level: MessageLevel.success,
        });
    };

    return html`<button
        class="pf-c-button ${control ? "pf-m-control" : "pf-m-plain"}"
        type="button"
        aria-label=${headline}
        @click=${open}
    >
        <pf-tooltip position="top" content=${headline}>
            <i class="fas fa-sync-alt" aria-hidden="true"></i>
        </pf-tooltip>
    </button>`;
}

/** Rotates a token's key. No rotate response carries it, so the copy button fetches it after. */
export const IconTokenRotateButton = (identifier: string) =>
    IconRotateSecretButton({
        rotate: () => aki(CoreApi).coreTokensRotateSecretCreate({ identifier }),
    });
