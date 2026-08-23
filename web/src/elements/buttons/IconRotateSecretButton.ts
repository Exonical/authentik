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
    /** Calls the rotate endpoint. On success a refresh event is dispatched from the button. */
    rotate: () => Promise<unknown>;
    header: string;
    body: SlottedTemplateResult;
    successMessage: string;
    errorMessage: string;
}

/**
 * An icon button that asks for confirmation before replacing a secret with a newly generated one.
 * The confirmation opens in the top layer, so it also works inside a form modal.
 * Pass `control` to render it as a bordered input-group control next to an input.
 */
export function IconRotateSecretButton(
    { rotate, header, body, successMessage, errorMessage }: RotateSecretProps,
    control = false,
): SlottedTemplateResult {
    const close = (event: Event, returnValue?: string) =>
        (event.target as HTMLElement).closest("dialog")?.close(returnValue);

    const open = (event: Event) => {
        let rotated = false;
        const confirm = (click: Event) =>
            rotate().then(
                () => {
                    rotated = true;
                    close(click, "submitted");
                },
                async (error: unknown) =>
                    showMessage({
                        message: msg(
                            str`${errorMessage}: ${pluckErrorDetail(await parseAPIResponseError(error))}`,
                        ),
                        level: MessageLevel.error,
                    }),
            );

        return renderDialog(
            html`<ak-modal headline=${header}>
                <div class="pf-c-content">${body}</div>
                <button slot="actions" type="button" class="pf-c-button pf-m-link" @click=${close}>
                    ${msg("Cancel")}
                </button>
                <button
                    slot="actions"
                    type="button"
                    class="pf-c-button pf-m-danger"
                    @click=${confirm}
                >
                    ${msg("Rotate", { id: "secret-rotate.confirm.action" })}
                </button>
            </ak-modal>`,
            { invokerElement: event.currentTarget as Element },
        ).then(() => {
            if (rotated) {
                showMessage({ message: successMessage, level: MessageLevel.success });
            }
        });
    };

    return html`<button
        class="pf-c-button ${control ? "pf-m-control" : "pf-m-plain"}"
        type="button"
        aria-label=${header}
        @click=${open}
    >
        <pf-tooltip position="top" content=${header}>
            <i class="fas fa-sync-alt" aria-hidden="true"></i>
        </pf-tooltip>
    </button>`;
}
