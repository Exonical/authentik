import "#elements/forms/ConfirmationForm";
import "@patternfly/elements/pf-tooltip/pf-tooltip.js";

import { SlottedTemplateResult } from "#elements/types";

import { msg } from "@lit/localize";
import { html, TemplateResult } from "lit";

export interface RotateSecretProps {
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

function RotateSecretConfirm(
    { onConfirm, header, body, successMessage, errorMessage }: RotateSecretProps,
    trigger: TemplateResult,
): SlottedTemplateResult {
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
        ${trigger}
        <div slot="modal"></div>
    </ak-forms-confirm>`;
}

/**
 * An icon button that opens a confirmation before replacing a secret with a newly generated one.
 * Pass `control` to render it as a bordered input-group control next to an input.
 */
export function IconRotateSecretButton(
    props: RotateSecretProps,
    control = false,
): SlottedTemplateResult {
    return RotateSecretConfirm(
        props,
        html`<button
            slot="trigger"
            class="pf-c-button ${control ? "pf-m-control" : "pf-m-plain"}"
            type="button"
            aria-label=${props.buttonLabel}
        >
            <pf-tooltip position="top" content=${props.buttonLabel}>
                <i class="fas fa-sync-alt" aria-hidden="true"></i>
            </pf-tooltip>
        </button>`,
    );
}
