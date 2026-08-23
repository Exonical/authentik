import "#components/ak-visibility-toggle";

import { EVENT_REFRESH } from "#common/constants";

import { AKElement } from "#elements/Base";
import { IconCopyButton } from "#elements/buttons/IconCopyButton";

import { msg } from "@lit/localize";
import { css, html } from "lit";
import { customElement, property, state } from "lit/decorators.js";

import PFButton from "@patternfly/patternfly/components/Button/button.css";

/**
 * Shows a secret masked, with controls to reveal and copy it.
 *
 * @element ak-secret-value
 * @slot - Additional controls, such as a rotate button, rendered after the copy button.
 */
@customElement("ak-secret-value")
export class SecretValue extends AKElement {
    static styles = [
        PFButton,
        css`
            :host {
                display: inline-flex;
                align-items: center;
                flex-wrap: wrap;
                gap: var(--pf-global--spacer--sm);
            }
            code {
                font-family: var(--pf-global--FontFamily--monospace);
                word-break: break-all;
            }
            .actions {
                display: inline-flex;
                align-items: center;
            }
        `,
    ];

    /**
     * The secret, when the caller already has it.
     */
    @property({ type: String })
    public value: string | null = null;

    /**
     * Loads the secret on first reveal or copy, for secrets only handed out on request.
     * Forgotten again on a refresh event, such as after a rotation in the slot.
     */
    @property({ attribute: false })
    public fetch?: () => Promise<string>;

    @property({ type: String, attribute: "entity-label" })
    public entityLabel = msg("Secret", { id: "secret-value.entity-label" });

    @state()
    protected revealed = false;

    constructor() {
        super();
        this.addEventListener(EVENT_REFRESH, () => {
            if (this.fetch) {
                this.value = null;
                this.revealed = false;
            }
        });
    }

    async #load(): Promise<string> {
        if (this.value === null && this.fetch) {
            this.value = await this.fetch();
        }
        return this.value ?? "";
    }

    render() {
        return html`<code>${this.revealed ? this.value : "••••••••••••"}</code>
            <span class="actions">
                <ak-visibility-toggle
                    plain
                    ?open=${this.revealed}
                    show-message=${msg("Show secret", { id: "secret-value.show.label" })}
                    hide-message=${msg("Hide secret", { id: "secret-value.hide.label" })}
                    @click=${async () => {
                        await this.#load();
                        this.revealed = !this.revealed;
                    }}
                ></ak-visibility-toggle>
                ${IconCopyButton({
                    source: () =>
                        this.#load().then((value) => new Blob([value], { type: "text/plain" })),
                    entityLabel: this.entityLabel,
                })}
                <slot></slot>
            </span>`;
    }
}

declare global {
    interface HTMLElementTagNameMap {
        "ak-secret-value": SecretValue;
    }
}
