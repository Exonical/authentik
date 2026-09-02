import "#admin/providers/RelatedApplicationButton";
import "#admin/providers/kerberos/KerberosProviderForm";
import "#admin/providers/kerberos/RealmTrustList";
import "#admin/providers/kerberos/ServicePrincipalList";
import "#admin/rbac/ak-rbac-object-permission-page";
import "#admin/events/ObjectChangelog";
import "#elements/Tabs";
import "#elements/buttons/ModalButton";

import { aki } from "#common/api/client";

import { AKElement } from "#elements/Base";
import { SlottedTemplateResult } from "#elements/types";

import { setPageDetails } from "#components/ak-page-navbar";

import {
    enctypeName,
    principalUsernameAttributeName,
} from "#admin/providers/kerberos/KerberosProviderFormForm";

import {
    CertificateKeyPair,
    CryptoApi,
    KerberosProvider,
    ModelEnum,
    ProvidersApi,
} from "@goauthentik/api";

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

const descriptionLabels: Record<string, string> = {
    "kerberos.provider-name.term": msg("Name", { id: "kerberos.provider-name.term" }),
    "kerberos.realm-name.term": msg("Realm", { id: "kerberos.realm-name.term" }),
    "kerberos.default-domain.term": msg("Default domain", {
        id: "kerberos.default-domain.term",
    }),
    "kerberos.maximum-ticket-lifetime.term": msg("Maximum ticket lifetime", {
        id: "kerberos.maximum-ticket-lifetime.term",
    }),
    "kerberos.maximum-ticket-renew-lifetime.term": msg("Maximum ticket renew lifetime", {
        id: "kerberos.maximum-ticket-renew-lifetime.term",
    }),
    "kerberos.default-ticket-lifetime.term": msg("Default ticket lifetime", {
        id: "kerberos.default-ticket-lifetime.term",
    }),
    "kerberos.default-ticket-renew-lifetime.term": msg("Default ticket renew lifetime", {
        id: "kerberos.default-ticket-renew-lifetime.term",
    }),
    "kerberos.allowed-enctypes.term": msg("Allowed encryption types", {
        id: "kerberos.allowed-enctypes.term",
    }),
    "kerberos.require-preauthentication.term": msg("Require preauthentication", {
        id: "kerberos.require-preauthentication.term",
    }),
    "kerberos.udp-enabled.term": msg("UDP enabled", {
        id: "kerberos.udp-enabled.term",
    }),
    "kerberos.tcp-enabled.term": msg("TCP enabled", {
        id: "kerberos.tcp-enabled.term",
    }),
    "kerberos.kpasswd-enabled.term": msg("Password changes enabled", {
        id: "kerberos.kpasswd-enabled.term",
    }),
    "kerberos.kkdcp.enabled.term": msg("KDC Proxy enabled", {
        id: "kerberos.kkdcp.enabled.term",
    }),
    "kerberos.spake.enabled.term": msg("SPAKE preauthentication enabled", {
        id: "kerberos.spake.enabled.term",
    }),
    "kerberos.pkinit.freshness.term": msg("Require PKINIT freshness", {
        id: "kerberos.pkinit.freshness.term",
    }),
    "kerberos.anonymous-pkinit.enabled.term": msg("Anonymous PKINIT enabled", {
        id: "kerberos.anonymous-pkinit.enabled.term",
    }),
    "kerberos.pkinit-indicators.term": msg("PKINIT indicators", {
        id: "kerberos.pkinit-indicators.term",
    }),
    "kerberos.spake-indicators.term": msg("SPAKE indicators", {
        id: "kerberos.spake-indicators.term",
    }),
    "kerberos.encrypted-challenge-indicator.term": msg("Encrypted-challenge indicator", {
        id: "kerberos.encrypted-challenge-indicator.term",
    }),
    "kerberos.otp.enabled.term": msg("OTP preauthentication enabled", {
        id: "kerberos.otp.enabled.term",
    }),
    "kerberos.otp-indicators.term": msg("OTP indicators", {
        id: "kerberos.otp-indicators.term",
    }),
    "kerberos.forwardable.term": msg("Forwardable", { id: "kerberos.forwardable.term" }),
    "kerberos.renewable.term": msg("Renewable", { id: "kerberos.renewable.term" }),
    "kerberos.proxiable.term": msg("Proxiable", { id: "kerberos.proxiable.term" }),
    "kerberos.kdc-audit-enabled.term": msg("KDC audit events enabled", {
        id: "kerberos.kdc-audit-enabled.term",
    }),
    "kerberos.kadmin-enabled.term": msg("Kerberos administration enabled", {
        id: "kerberos.kadmin-enabled.term",
    }),
    "kerberos.kadmin-acl.term": msg("Kadmin ACL", {
        id: "kerberos.kadmin-acl.term",
    }),
    "kerberos.principal-username-attribute.term": msg("Principal username attribute", {
        id: "kerberos.principal-username-attribute.term",
    }),
    "kerberos.pkinit.kdc-certificate.term": msg("KDC signing certificate", {
        id: "kerberos.pkinit.kdc-certificate.term",
    }),
    "kerberos.pkinit.client-ca.term": msg("Client CA certificate", {
        id: "kerberos.pkinit.client-ca.term",
    }),
    "kerberos.kkdcp.certificate.term": msg("KDC Proxy TLS certificate", {
        id: "kerberos.kkdcp.certificate.term",
    }),
};

@customElement("ak-provider-kerberos-view")
export class KerberosProviderViewPage extends AKElement {
    @property({ type: Number })
    providerID?: number;

    @state()
    provider?: KerberosProvider;

    @state()
    pkinitCertificate: CertificateKeyPair | null = null;

    @state()
    pkinitClientCa: CertificateKeyPair | null = null;

    @state()
    kkdcpCertificate: CertificateKeyPair | null = null;

    static styles: CSSResult[] = [
        PFButton,
        PFPage,
        PFDisplay,
        PFContent,
        PFCard,
        PFDescriptionList,
        PFSizing,
    ];

    fetchCertificate(kpUuid: string) {
        return aki(CryptoApi).cryptoCertificatekeypairsRetrieve({ kpUuid });
    }

    fetchPkinitCertificate(kpUuid: string) {
        this.fetchCertificate(kpUuid).then((certificate) => {
            this.pkinitCertificate = certificate;
            this.requestUpdate("pkinitCertificate");
        });
    }

    fetchPkinitClientCa(kpUuid: string) {
        this.fetchCertificate(kpUuid).then((certificate) => {
            this.pkinitClientCa = certificate;
            this.requestUpdate("pkinitClientCa");
        });
    }

    fetchProvider(id: number) {
        aki(ProvidersApi)
            .providersKerberosRetrieve({ id })
            .then((provider) => {
                this.provider = provider;
                if (!provider.pkinitCertificate) {
                    this.pkinitCertificate = null;
                } else {
                    this.fetchPkinitCertificate(provider.pkinitCertificate);
                }
                if (!provider.pkinitClientCa) {
                    this.pkinitClientCa = null;
                } else {
                    this.fetchPkinitClientCa(provider.pkinitClientCa);
                }
                if (!provider.kkdcpCertificate) {
                    this.kkdcpCertificate = null;
                } else {
                    this.fetchCertificate(provider.kkdcpCertificate).then((certificate) => {
                        this.kkdcpCertificate = certificate;
                        this.requestUpdate("kkdcpCertificate");
                    });
                }
            });
    }

    willUpdate(changedProperties: PropertyValues<this>) {
        if (changedProperties.has("providerID") && this.providerID) {
            this.fetchProvider(this.providerID);
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
                                                "Password changes enabled",
                                                this.provider.kpasswdEnabled,
                                                "kerberos.kpasswd-enabled.term",
                                            )}
                                            ${this.renderBoolean(
                                                "KDC audit events enabled",
                                                this.provider.kdcAuditEnabled,
                                                "kerberos.kdc-audit-enabled.term",
                                            )}
                                            ${this.renderBoolean(
                                                "Kerberos administration enabled",
                                                this.provider.kadminEnabled,
                                                "kerberos.kadmin-enabled.term",
                                            )}
                                            ${this.renderDescription(
                                                "Kadmin ACL",
                                                this.provider.kadminAcl?.join(", ") || "-",
                                                "kerberos.kadmin-acl.term",
                                            )}
                                            ${this.renderBoolean(
                                                "KDC Proxy enabled",
                                                this.provider.kkdcpEnabled,
                                                "kerberos.kkdcp.enabled.term",
                                            )}
                                            ${this.renderBoolean(
                                                "SPAKE preauthentication enabled",
                                                this.provider.spakeEnabled,
                                                "kerberos.spake.enabled.term",
                                            )}
                                            ${this.renderBoolean(
                                                "Require PKINIT freshness",
                                                this.provider.pkinitRequireFreshness,
                                                "kerberos.pkinit.freshness.term",
                                            )}
                                            ${this.renderBoolean(
                                                "Anonymous PKINIT enabled",
                                                this.provider.anonymousPkinitEnabled,
                                                "kerberos.anonymous-pkinit.enabled.term",
                                            )}
                                            ${this.renderBoolean(
                                                "OTP preauthentication enabled",
                                                this.provider.otpEnabled,
                                                "kerberos.otp.enabled.term",
                                            )}
                                            ${this.renderDescription(
                                                "OTP indicators",
                                                this.provider.otpIndicators?.join(", ") || "-",
                                                "kerberos.otp-indicators.term",
                                            )}
                                            ${this.renderDescription(
                                                "PKINIT indicators",
                                                this.provider.pkinitIndicators?.join(", ") || "-",
                                                "kerberos.pkinit-indicators.term",
                                            )}
                                            ${this.renderDescription(
                                                "SPAKE indicators",
                                                this.provider.spakeIndicators?.join(", ") || "-",
                                                "kerberos.spake-indicators.term",
                                            )}
                                            ${this.renderDescription(
                                                "Encrypted-challenge indicator",
                                                this.provider.encryptedChallengeIndicator || "-",
                                                "kerberos.encrypted-challenge-indicator.term",
                                            )}
                                            ${this.renderBoolean(
                                                "MS-PAC enabled",
                                                this.provider.pacEnabled,
                                                "kerberos.pac.enabled.term",
                                            )}
                                            ${this.renderDescription(
                                                "Realm SID",
                                                this.provider.realmSid || "-",
                                                "kerberos.pac.realm-sid.term",
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
                                                principalUsernameAttributeName(
                                                    this.provider.principalUsernameAttribute,
                                                ),
                                                "kerberos.principal-username-attribute.term",
                                            )}
                                            ${this.renderDescription(
                                                "KDC signing certificate",
                                                this.pkinitCertificate?.name ?? "-",
                                                "kerberos.pkinit.kdc-certificate.term",
                                            )}
                                            ${this.renderDescription(
                                                "Client CA certificate",
                                                this.pkinitClientCa?.name ?? "-",
                                                "kerberos.pkinit.client-ca.term",
                                            )}
                                            ${this.renderDescription(
                                                "KDC Proxy TLS certificate",
                                                this.kkdcpCertificate?.name ?? "-",
                                                "kerberos.kkdcp.certificate.term",
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
                    <div class="pf-c-card pf-l-grid__item pf-m-12-col">
                        <div class="pf-c-card__title">
                            ${msg("Service principals", {
                                id: "kerberos.service-principal.section.title",
                            })}
                        </div>
                        <ak-kerberos-service-principal-list
                            .provider=${this.provider}
                        ></ak-kerberos-service-principal-list>
                    </div>
                    <div class="pf-c-card pf-l-grid__item pf-m-12-col">
                        <div class="pf-c-card__title">
                            ${msg("Realm trusts", {
                                id: "kerberos.realm-trust.section.title",
                            })}
                        </div>
                        <ak-kerberos-realm-trust-list
                            .provider=${this.provider}
                        ></ak-kerberos-realm-trust-list>
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
                <span class="pf-c-description-list__text">${descriptionLabels[id] ?? label}</span>
            </dt>
            <dd class="pf-c-description-list__description">
                <div class="pf-c-description-list__text">${value}</div>
            </dd>
        </div>`;
    }

    renderBoolean(label: string, value: boolean | undefined, id: string): SlottedTemplateResult {
        return this.renderDescription(
            label,
            value
                ? msg("Yes", { id: "common.boolean.yes" })
                : msg("No", { id: "common.boolean.no" }),
            id,
        );
    }
}

declare global {
    interface HTMLElementTagNameMap {
        "ak-provider-kerberos-view": KerberosProviderViewPage;
    }
}
