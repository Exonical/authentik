import "#admin/providers/RelatedApplicationButton";
import "#admin/providers/kerberos/KerberosProviderForm";
import "#elements/buttons/ModalButton";

import { aki } from "#common/api/client";

import { AKElement } from "#elements/Base";

import { KerberosProvider, ProvidersApi } from "@goauthentik/api";

import { msg } from "@lit/localize";
import { html, nothing, PropertyValues } from "lit";
import { customElement, property, state } from "lit/decorators.js";

@customElement("ak-provider-kerberos-view")
export class KerberosProviderViewPage extends AKElement {
    @property({ type: Number })
    providerID?: number;

    @state()
    provider?: KerberosProvider;

    willUpdate(changedProperties: PropertyValues<this>) {
        if (changedProperties.has("providerID") && this.providerID) {
            aki(ProvidersApi)
                .providersKerberosRetrieve({ id: this.providerID })
                .then((provider) => (this.provider = provider));
        }
    }

    render() {
        if (!this.provider) {
            return nothing;
        }

        return html`
            <main class="pf-c-page__main-section">
                <div class="pf-c-card">
                    <div class="pf-c-card__body">
                        <dl class="pf-c-description-list pf-m-3-col-on-lg">
                            <div class="pf-c-description-list__group">
                                <dt class="pf-c-description-list__term">
                                    ${msg("Name", { id: "kerberos.provider-name.term" })}
                                </dt>
                                <dd class="pf-c-description-list__description">
                                    ${this.provider.name}
                                </dd>
                            </div>
                            <div class="pf-c-description-list__group">
                                <dt class="pf-c-description-list__term">
                                    ${msg("Realm", { id: "kerberos.realm-name.term" })}
                                </dt>
                                <dd class="pf-c-description-list__description">
                                    ${this.provider.realmName}
                                </dd>
                            </div>
                            <div class="pf-c-description-list__group">
                                <dt class="pf-c-description-list__term">
                                    ${msg("Assigned application", {
                                        id: "kerberos.assigned-application.term",
                                    })}
                                </dt>
                                <dd class="pf-c-description-list__description">
                                    <ak-provider-related-application
                                        .provider=${this.provider}
                                    ></ak-provider-related-application>
                                </dd>
                            </div>
                        </dl>
                    </div>
                    <div class="pf-c-card__footer">
                        <ak-forms-modal>
                            <span slot="submit"
                                >${msg("Save Changes", {
                                    id: "kerberos.save-changes.label",
                                })}</span
                            >
                            <span slot="header"
                                >${msg("Update Kerberos Provider", {
                                    id: "kerberos.update-provider.title",
                                })}</span
                            >
                            <ak-provider-kerberos-form
                                slot="form"
                                .instancePk=${this.provider.pk}
                            ></ak-provider-kerberos-form>
                            <button slot="trigger" class="pf-c-button pf-m-primary">
                                ${msg("Edit", { id: "kerberos.edit.label" })}
                            </button>
                        </ak-forms-modal>
                    </div>
                </div>
            </main>
        `;
    }
}

declare global {
    interface HTMLElementTagNameMap {
        "ak-provider-kerberos-view": KerberosProviderViewPage;
    }
}
