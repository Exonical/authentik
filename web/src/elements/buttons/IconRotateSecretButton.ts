import "#elements/dialogs/ak-modal";
import "@patternfly/elements/pf-tooltip/pf-tooltip.js";

import { parseAPIResponseError, pluckErrorDetail } from "#common/errors/network";
import { AKDiscardChangesEvent } from "#common/events";
import { MessageLevel } from "#common/messages";

import { renderDialog } from "#elements/dialogs/utils";
import { showMessage } from "#elements/messages/MessageContainer";
import { SlottedTemplateResult } from "#elements/types";

import { msg, str } from "@lit/localize";
import { html, nothing } from "lit";

export interface RotateSecretProps {
    /** Calls the rotate endpoint. On success the button dispatches refresh and discard events. */
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
 *
 * Rotating replaces the object being edited, so a surrounding form is rebuilt from the new
 * server-side state and whatever the user had typed into it is discarded.
 */
export function IconRotateSecretButton(
    { rotate, header, body, successMessage, errorMessage }: RotateSecretProps,
    control = false,
): SlottedTemplateResult {
    // Resolve the dialog before any await: event targets inside a shadow tree are cleared once
    // dispatch finishes.
    const dialogOf = (event: Event) => (event.currentTarget as HTMLElement).closest("dialog");
    const close = (event: Event) => dialogOf(event)?.close();

    const open = (event: Event) => {
        const invoker = event.currentTarget as HTMLElement;
        const inForm = !!invoker.closest("form");

        let rotated = false;
        const confirm = (click: Event) => {
            const dialog = dialogOf(click);
            return rotate().then(
                () => {
                    rotated = true;

                    // Dispatched before the dialog closes: closing refreshes the surrounding form,
                    // which takes the invoker out of the DOM along with the fields being rebuilt.
                    invoker.dispatchEvent(new AKDiscardChangesEvent());

                    dialog?.close("submitted");
                },
                async (error: unknown) =>
                    showMessage({
                        message: msg(
                            str`${errorMessage}: ${pluckErrorDetail(await parseAPIResponseError(error))}`,
                        ),
                        level: MessageLevel.error,
                    }),
            );
        };

        return renderDialog(
            html`<ak-modal headline=${header}>
                <div class="pf-c-content">
                    ${body}
                    ${inForm
                        ? html`<p>
                              ${msg("Unsaved changes to this form are discarded.", {
                                  id: "secret-rotate.confirm.discard",
                              })}
                          </p>`
                        : nothing}
                </div>
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
            { invokerElement: invoker },
        ).then(() => {
            if (!rotated) return;

            showMessage({ message: successMessage, level: MessageLevel.success });
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
