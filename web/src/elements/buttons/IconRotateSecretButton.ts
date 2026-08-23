import "#elements/dialogs/ak-modal";
import "@patternfly/elements/pf-tooltip/pf-tooltip.js";

import { parseAPIResponseError, pluckErrorDetail } from "#common/errors/network";
import { AKRefreshEvent } from "#common/events";
import { MessageLevel } from "#common/messages";

import { renderConfirmation } from "#elements/dialogs/utils";
import { showMessage } from "#elements/messages/MessageContainer";
import { SlottedTemplateResult } from "#elements/types";

import { msg, str } from "@lit/localize";
import { html, nothing } from "lit";

/** The API's rotate response. `secret` is null for secrets that reads never hand out. */
export interface RotatedSecret {
    secret?: string | null;
}

/** Rotation reads the same way for every secret, so the warning is not written per call site. */
const rotateWarning = msg(
    "The old value stops working. Everything using it has to be updated with the new one.",
    { id: "secret-rotate.confirm.warning" },
);

const rotateFormWarning = msg("Rotating applies immediately, even if you don't save this form.", {
    id: "secret-rotate.confirm.unsaved",
});

export interface RotateSecretProps {
    /** Calls the rotate endpoint. */
    rotate: () => Promise<RotatedSecret>;
    /** What is being rotated, e.g. "Client Secret". Names the button and every message. */
    entityLabel: string;
    /** Hands the new secret to the field that owns it, instead of reloading the page around it. */
    apply?: (secret: string) => void;
}

/**
 * An icon button that asks for confirmation before replacing a secret with a newly generated one.
 * The confirmation opens in the top layer, so it also works inside a form modal.
 * Pass `control` to render it as a bordered input-group control next to an input.
 *
 * Prefer the `rotate` property of {@linkcode AkHiddenTextInput}; this is for secrets with no field
 * to sit next to, such as a table cell.
 */
export function IconRotateSecretButton(
    { rotate, entityLabel, apply }: RotateSecretProps,
    control = false,
): SlottedTemplateResult {
    const headline = msg(str`Rotate ${entityLabel}`, { id: "secret-rotate.confirm.header" });

    const open = async (event: Event) => {
        // Read the invoker before any await: event targets inside a shadow tree are cleared once
        // dispatch finishes.
        const invoker = event.currentTarget as HTMLElement;

        let secret: string | null | undefined;

        const confirmed = await renderConfirmation(
            html`<p>${rotateWarning}</p>
                ${invoker.closest("form") ? html`<p>${rotateFormWarning}</p>` : nothing}`,
            async () => {
                try {
                    secret = (await rotate()).secret;
                } catch (error) {
                    showMessage({
                        message: msg(
                            str`Failed to rotate ${entityLabel}: ${pluckErrorDetail(await parseAPIResponseError(error))}`,
                            { id: "secret-rotate.error" },
                        ),
                        level: MessageLevel.error,
                    });

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

        // Handing the secret to its own field leaves the rest of an open form untouched. Without
        // one, whatever is showing the secret has to reload to catch up.
        if (secret && apply) apply(secret);
        else invoker.dispatchEvent(new AKRefreshEvent());

        showMessage({
            message: msg(str`Successfully rotated ${entityLabel}.`, {
                id: "secret-rotate.success",
            }),
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
