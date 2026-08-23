import "#elements/dialogs/ak-modal";
import "@patternfly/elements/pf-tooltip/pf-tooltip.js";

import { parseAPIResponseError, pluckErrorDetail } from "#common/errors/network";
import { MessageLevel } from "#common/messages";

import { renderDialog } from "#elements/dialogs/utils";
import { showMessage } from "#elements/messages/MessageContainer";
import { SlottedTemplateResult } from "#elements/types";

import { msg, str } from "@lit/localize";
import { html } from "lit";

export interface RotateSecretProps {
    /**
     * Calls the rotate endpoint. On success a refresh event is dispatched from the button.
     */
    onConfirm: () => Promise<unknown>;
    header: string;
    body: SlottedTemplateResult;
    successMessage: string;
    errorMessage: string;
    buttonLabel: string;
}

/**
 * An icon button that asks for confirmation before replacing a secret with a newly generated one.
 * The confirmation opens in the top layer, so it can also be used inside a form modal.
 * Pass `control` to render it as a bordered input-group control next to an input.
 */
export function IconRotateSecretButton(
    { onConfirm, header, body, successMessage, errorMessage, buttonLabel }: RotateSecretProps,
    control = false,
): SlottedTemplateResult {
    const closeModal = (event: Event, returnValue?: string) =>
        (event.target as HTMLElement).closest("ak-modal")?.close(returnValue);

    const confirm = (event: Event) =>
        onConfirm().then(
            () => {
                showMessage({ message: successMessage, level: MessageLevel.success });
                closeModal(event, "submitted");
            },
            async (error: unknown) => {
                const parsed = await parseAPIResponseError(error);
                showMessage({
                    message: msg(str`${errorMessage}: ${pluckErrorDetail(parsed)}`),
                    level: MessageLevel.error,
                });
            },
        );

    const open = (event: Event) =>
        renderDialog(
            html`<ak-modal headline=${header}>
                <div class="pf-c-content">${body}</div>
                <button
                    slot="actions"
                    type="button"
                    class="pf-c-button pf-m-link"
                    @click=${closeModal}
                >
                    ${msg("Cancel")}
                </button>
                <button
                    slot="actions"
                    type="button"
                    class="pf-c-button pf-m-danger"
                    @click=${confirm}
                >
                    ${msg("Rotate", {
                        id: "secret-rotate.confirm.action",
                        desc: "Label for the confirmation button that rotates a secret.",
                    })}
                </button>
            </ak-modal>`,
            { invokerElement: event.currentTarget as Element },
        );

    return html`<button
        class="pf-c-button ${control ? "pf-m-control" : "pf-m-plain"}"
        type="button"
        aria-label=${buttonLabel}
        @click=${open}
    >
        <pf-tooltip position="top" content=${buttonLabel}>
            <i class="fas fa-sync-alt" aria-hidden="true"></i>
        </pf-tooltip>
    </button>`;
}
