import "#elements/forms/ConfirmationForm";
import "@patternfly/elements/pf-tooltip/pf-tooltip.js";

import { SlottedTemplateResult } from "#elements/types";

import { msg } from "@lit/localize";
import { html } from "lit";

export interface IconRotateSecretButtonProps {
    /**
     * Calls the rotate endpoint. The confirmation form surfaces errors and
     * dispatches a refresh event on success.
     */
    onConfirm: () => Promise<unknown>;
    header: string;
    body: SlottedTemplateResult;
    successMessage: string;
    errorMessage: string;
    buttonLabel: string;
}

/**
 * An icon button that opens a confirmation before replacing a secret with a newly generated one.
 */
export function IconRotateSecretButton({
    onConfirm,
    header,
    body,
    successMessage,
    errorMessage,
    buttonLabel,
}: IconRotateSecretButtonProps): SlottedTemplateResult {
    return html`<ak-forms-confirm
        successMessage=${successMessage}
        errorMessage=${errorMessage}
        action=${msg("Rotate", {
            id: "secret-rotate.confirm.action",
            desc: "Label for the confirmation button that rotates a secret.",
        })}
        .onConfirm=${onConfirm}
    >
        <span slot="header">${header}</span>
        <div slot="body" class="pf-c-content">${body}</div>
        <button
            slot="trigger"
            class="pf-c-button pf-m-plain"
            type="button"
            aria-label=${buttonLabel}
        >
            <pf-tooltip position="top" content=${buttonLabel}>
                <i class="fas fa-sync-alt" aria-hidden="true"></i>
            </pf-tooltip>
        </button>
        <div slot="modal"></div>
    </ak-forms-confirm>`;
}
