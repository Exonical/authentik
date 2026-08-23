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
 */
export function IconRotateSecretButton(props: RotateSecretProps): SlottedTemplateResult {
    return RotateSecretConfirm(
        props,
        html`<button
            slot="trigger"
            class="pf-c-button pf-m-plain"
            type="button"
            aria-label=${props.buttonLabel}
        >
            <pf-tooltip position="top" content=${props.buttonLabel}>
                <i class="fas fa-sync-alt" aria-hidden="true"></i>
            </pf-tooltip>
        </button>`,
    );
}

/**
 * A labelled secondary button variant of {@linkcode IconRotateSecretButton}, for forms.
 */
export function RotateSecretButton(props: RotateSecretProps): SlottedTemplateResult {
    return RotateSecretConfirm(
        props,
        html`<button slot="trigger" class="pf-c-button pf-m-secondary" type="button">
            ${props.buttonLabel}
        </button>`,
    );
}
