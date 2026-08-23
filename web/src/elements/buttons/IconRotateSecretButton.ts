import "#elements/dialogs/ak-modal";
import "@patternfly/elements/pf-tooltip/pf-tooltip.js";

import { parseAPIResponseError, pluckErrorDetail } from "#common/errors/network";
import { MessageLevel } from "#common/messages";

import { renderDialog } from "#elements/dialogs/utils";
import { showMessage } from "#elements/messages/MessageContainer";
import { SlottedTemplateResult } from "#elements/types";

import { msg, str } from "@lit/localize";
import { html, nothing } from "lit";

export interface RotateSecretProps {
    /** Calls the rotate endpoint. On success a refresh event is dispatched from the button. */
    rotate: () => Promise<unknown>;
    /** What is being rotated, e.g. "Client Secret". Names the button and every message. */
    entityLabel: string;
    /** What stops working once the secret is replaced, shown in the confirmation. */
    warning?: string | null;
}

/**
 * An icon button that asks for confirmation before replacing a secret with a newly generated one.
 * The confirmation opens in the top layer, so it also works inside a form modal.
 * Pass `control` to render it as a bordered input-group control next to an input.
 *
 * Prefer the `rotate` property of {@linkcode AkHiddenTextInput} over calling this directly; it
 * only makes sense on its own where a secret has no field to sit next to, such as a table cell.
 */
export function IconRotateSecretButton(
    { rotate, entityLabel, warning }: RotateSecretProps,
    control = false,
): SlottedTemplateResult {
    const header = msg(str`Rotate ${entityLabel}`, { id: "secret-rotate.confirm.header" });

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
                    dialog?.close("submitted");
                },
                async (error: unknown) =>
                    showMessage({
                        message: msg(
                            str`Failed to rotate ${entityLabel}: ${pluckErrorDetail(await parseAPIResponseError(error))}`,
                            { id: "secret-rotate.error" },
                        ),
                        level: MessageLevel.error,
                    }),
            );
        };

        return renderDialog(
            html`<ak-modal headline=${header}>
                <div class="pf-c-content">
                    ${warning ? html`<p>${warning}</p>` : nothing}
                    ${inForm
                        ? html`<p>
                              ${msg(
                                  "Rotating applies immediately, even if you don't save this form.",
                                  { id: "secret-rotate.confirm.unsaved" },
                              )}
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

            showMessage({
                message: msg(str`Successfully rotated ${entityLabel}.`, {
                    id: "secret-rotate.success",
                }),
                level: MessageLevel.success,
            });
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
