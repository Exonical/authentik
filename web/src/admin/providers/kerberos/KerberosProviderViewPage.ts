import "#admin/providers/RelatedApplicationButton";
import "#admin/providers/kerberos/KerberosProviderForm";
import "#admin/rbac/ak-rbac-object-permission-page";
import "#admin/events/ObjectChangelog";
import "#elements/Tabs";
import "#elements/buttons/ModalButton";

import { aki } from "#common/api/client";

import { AKElement } from "#elements/Base";
import { SlottedTemplateResult } from "#elements/types";

import { setPageDetails } from "#components/ak-page-navbar";

import { enctypeName } from "#admin/providers/kerberos/KerberosProviderFormForm";

import { KerberosProvider, ModelEnum, ProvidersApi } from "@goauthentik/api";

import { msg } from "@lit/localize";
import { CSSResult, html, nothing, PropertyValues } from "lit";
import { customElement, property, state } from "lit/decorators.js";

import PFButton from "@patternfly/patternfly/components/Button/button.css";
import PFCard from "@patternfly/patternfly/components/Card/card.css";
import PFContent from "@patternfly/patternfly/components/Content/content.css";
import PFDescriptionList from "@patternfly/patternfly/components/DescriptionList/description-list.css";
import PFPage from "@patternfly/patternfly/components/Page/page.css";
import PFDisplay from "@patternfly/patternfly/utilities/Display/display.css";
import PFSizing from "@patternfly/patternfly/utilities/Sizing/sizing.css";

@customElement("ak-provider-kerberos-view")
export class KerberosProviderViewPage extends AKElement {
    @property({ type: Number })
    providerID?: number;

    @state()
    provider?: KerberosProvider;

    static styles: CSSResult[] = [
        PFButton,
        PFPage,
        PFDisplay,
        PFContent,
        PFCard,
        PFDescriptionList,
        PFSizing,
    ];

    willUpdate(changedProperties: PropertyValues<this>) {
        if (changedProperties.has("providerID") && this.providerID) {
            aki(ProvidersApi)
                .providersKerberosRetrieve({ id: this.providerID })
                .then((provider) => (this.provider = provider));
        }
    }

    updated() {
        setPageDetails({
            header: this.provider?.name,
            description: msg("Kerberos Provider", { id: "kerberos.provider.description" }),
            icon: "pf-icon pf-icon-middleware",
        });
    }

    render(): SlottedTemplateResult {
        if (!this.provider) {
            return nothing;
        }

        return html`<main part="main">
            <ak-tabs part="tabs">
                <section
                    role="tabpanel"
                    tabindex="0"
                    slot="page-overview"
                    id="page-overview"
                    aria-label="${msg("Overview", { id: "kerberos.overview.aria-label" })}"
                >
                    <div class="pf-c-page__main-section pf-m-no-padding-mobile">
                        <div class="pf-u-display-flex pf-u-justify-content-center">
                            <div class="pf-u-w-75">
                                <div class="pf-c-card">
                                    <div class="pf-c-card__body">
                                        <dl class="pf-c-description-list pf-m-3-col-on-lg">
                                            ${this.renderDescription(
                                                "Name",
                                                this.provider.name,
                                                "kerberos.provider-name.term",
                                            )}
                                            ${this.renderDescription(
                                                "Realm",
                                                this.provider.realmName,
                                                "kerberos.realm-name.term",
                                            )}
                                            ${this.renderDescription(
                                                "Default domain",
                                                this.provider.defaultDomain || "-",
                                                "kerberos.default-domain.term",
                                            )}
                                            <div class="pf-c-description-list__group">
                                                <dt class="pf-c-description-list__term">
                                                    <span class="pf-c-description-list__text"
                                                        >${msg("Assigned application", {
                                                            id: "kerberos.assigned-application.term",
                                                        })}</span
                                                    >
                                                </dt>
                                                <dd class="pf-c-description-list__description">
                                                    <div class="pf-c-description-list__text">
                                                        <ak-provider-related-application
                                                            .provider=${this.provider}
                                                        ></ak-provider-related-application>
                                                    </div>
                                                </dd>
                                            </div>
                                            ${this.renderDescription(
                                                "Maximum ticket lifetime",
                                                this.provider.maximumTicketLifetime ?? "-",
                                                "kerberos.maximum-ticket-lifetime.term",
                                            )}
                                            ${this.renderDescription(
                                                "Maximum ticket renew lifetime",
                                                this.provider.maximumTicketRenewLifetime ?? "-",
                                                "kerberos.maximum-ticket-renew-lifetime.term",
                                            )}
                                            ${this.renderDescription(
                                                "Default ticket lifetime",
                                                this.provider.defaultTicketLifetime ?? "-",
                                                "kerberos.default-ticket-lifetime.term",
                                            )}
                                            ${this.renderDescription(
                                                "Default ticket renew lifetime",
                                                this.provider.defaultTicketRenewLifetime ?? "-",
                                                "kerberos.default-ticket-renew-lifetime.term",
                                            )}
                                            ${this.renderDescription(
                                                "Allowed encryption types",
                                                this.provider.allowedEnctypes
                                                    ?.map(enctypeName)
                                                    .join(", ") ?? "-",
                                                "kerberos.allowed-enctypes.term",
                                            )}
                                            ${this.renderBoolean(
                                                "Require preauthentication",
                                                this.provider.requirePreauthentication,
                                                "kerberos.require-preauthentication.term",
                                            )}
                                            ${this.renderBoolean(
                                                "UDP enabled",
                                                this.provider.udpEnabled,
                                                "kerberos.udp-enabled.term",
                                            )}
                                            ${this.renderBoolean(
                                                "TCP enabled",
                                                this.provider.tcpEnabled,
                                                "kerberos.tcp-enabled.term",
                                            )}
                                            ${this.renderBoolean(
                                                "Forwardable",
                                                this.provider.forwardable,
                                                "kerberos.forwardable.term",
                                            )}
                                            ${this.renderBoolean(
                                                "Renewable",
                                                this.provider.renewable,
                                                "kerberos.renewable.term",
                                            )}
                                            ${this.renderBoolean(
                                                "Proxiable",
                                                this.provider.proxiable,
                                                "kerberos.proxiable.term",
                                            )}
                                            ${this.renderDescription(
                                                "Principal username attribute",
                                                this.provider.principalUsernameAttribute ??
                                                    "username",
                                                "kerberos.principal-username-attribute.term",
                                            )}
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
                            </div>
                        </div>
                    </div>
                </section>
                <section
                    role="tabpanel"
                    tabindex="0"
                    slot="page-changelog"
                    id="page-changelog"
                    aria-label="${msg("Changelog", { id: "kerberos.changelog.aria-label" })}"
                    class="pf-c-page__main-section pf-m-no-padding-mobile"
                >
                    <div class="pf-c-card">
                        <ak-object-changelog
                            targetModelPk=${this.provider.pk || ""}
                            targetModelName=${ModelEnum.AuthentikProvidersKerberosKerberosprovider}
                        ></ak-object-changelog>
                    </div>
                </section>
                <ak-rbac-object-permission-page
                    role="tabpanel"
                    tabindex="0"
                    slot="page-permissions"
                    id="page-permissions"
                    aria-label="${msg("Permissions", { id: "kerberos.permissions.aria-label" })}"
                    model=${ModelEnum.AuthentikProvidersKerberosKerberosprovider}
                    objectPk=${this.provider.pk}
                ></ak-rbac-object-permission-page>
            </ak-tabs>
        </main>`;
    }

    renderDescription(label: string, value: string, id: string): SlottedTemplateResult {
        return html`<div class="pf-c-description-list__group">
            <dt class="pf-c-description-list__term">
                <span class="pf-c-description-list__text">${msg(label, { id })}</span>
            </dt>
            <dd class="pf-c-description-list__description">
                <div class="pf-c-description-list__text">${value}</div>
            </dd>
        </div>`;
    }

    renderBoolean(label: string, value: boolean | undefined, id: string): SlottedTemplateResult {
        return this.renderDescription(
            label,
            value ? msg("Yes", { id: `${id}.yes` }) : msg("No", { id: `${id}.no` }),
            id,
        );
    }
}

declare global {
    interface HTMLElementTagNameMap {
        "ak-provider-kerberos-view": KerberosProviderViewPage;
    }
}
