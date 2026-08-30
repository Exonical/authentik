import "#admin/providers/kerberos/RealmTrustForm";
import "#elements/forms/ConfirmationForm";
import "#elements/forms/DeleteBulkForm";

import { aki } from "#common/api/client";
import { downloadFile } from "#common/download";

import { IconEditButton, ModalInvokerButton } from "#elements/dialogs";
import { PaginatedResponse, Table, TableColumn } from "#elements/table/Table";
import { SlottedTemplateResult } from "#elements/types";

import { RealmTrustForm } from "#admin/providers/kerberos/RealmTrustForm";

import {
    KerberosRealmTrust,
    KerberosProvider,
    DirectionEnum,
    ProvidersApi,
} from "@goauthentik/api";

import { msg } from "@lit/localize";
import { CSSResult, html } from "lit";
import { customElement, property } from "lit/decorators.js";

import PFDescriptionList from "@patternfly/patternfly/components/DescriptionList/description-list.css";

function keytabFilename(remoteRealm: string, direction: DirectionEnum): string {
    const safeName = remoteRealm.replace(/[^a-zA-Z0-9._-]+/g, "_");
    return `${safeName || "realm-trust"}-${direction}.keytab`;
}

function directionText(direction: DirectionEnum): {
    download: string;
    rotated: string;
    rotateError: string;
    rotateTitle: string;
    confirmation: string;
} {
    if (direction === DirectionEnum.Outgoing) {
        return {
            download: msg("Download outgoing keytab", {
                id: "kerberos.realm-trust.outgoing.download-keytab.label",
            }),
            rotated: msg("Successfully rotated outgoing realm trust keys.", {
                id: "kerberos.realm-trust.outgoing.rotate.success",
            }),
            rotateError: msg("Failed to rotate outgoing realm trust keys.", {
                id: "kerberos.realm-trust.outgoing.rotate.error",
            }),
            rotateTitle: msg("Rotate outgoing realm trust keys", {
                id: "kerberos.realm-trust.outgoing.rotate.title",
            }),
            confirmation: msg("Are you sure you want to rotate the outgoing realm trust keys?", {
                id: "kerberos.realm-trust.outgoing.rotate.confirmation",
            }),
        };
    }
    return {
        download: msg("Download incoming keytab", {
            id: "kerberos.realm-trust.incoming.download-keytab.label",
        }),
        rotated: msg("Successfully rotated incoming realm trust keys.", {
            id: "kerberos.realm-trust.incoming.rotate.success",
        }),
        rotateError: msg("Failed to rotate incoming realm trust keys.", {
            id: "kerberos.realm-trust.incoming.rotate.error",
        }),
        rotateTitle: msg("Rotate incoming realm trust keys", {
            id: "kerberos.realm-trust.incoming.rotate.title",
        }),
        confirmation: msg("Are you sure you want to rotate the incoming realm trust keys?", {
            id: "kerberos.realm-trust.incoming.rotate.confirmation",
        }),
    };
}

@customElement("ak-kerberos-realm-trust-list")
export class RealmTrustList extends Table<KerberosRealmTrust> {
    public static styles: CSSResult[] = [...super.styles, PFDescriptionList];

    public static override verboseName = msg("Realm trust", {
        id: "kerberos.realm-trust.verbose-name",
    });
    public static override verboseNamePlural = msg("Realm trusts", {
        id: "kerberos.realm-trust.verbose-name-plural",
    });

    protected override searchEnabled = true;
    protected override emptyStateMessage = msg("Create a realm trust to get started.", {
        id: "kerberos.realm-trust.empty-state",
    });

    public override checkbox = true;
    public override clearOnRefresh = true;
    public override searchPlaceholder = msg("Search for a remote realm...", {
        id: "kerberos.realm-trust.search.placeholder",
    });
    public override order = "remote_realm";

    @property({ attribute: false })
    public provider: KerberosProvider | null = null;

    protected override async apiEndpoint(): Promise<PaginatedResponse<KerberosRealmTrust>> {
        return aki(ProvidersApi).providersKerberosRealmTrustsList({
            ...(await this.defaultEndpointConfig()),
            provider: this.provider?.pk,
        });
    }

    protected override columns: TableColumn[] = [
        [msg("Remote realm", { id: "kerberos.realm-trust.remote-realm.column" }), "remoteRealm"],
        [msg("Intermediate realms", { id: "kerberos.realm-trust.capaths.column" }), "capaths"],
        [msg("Outgoing KVNO", { id: "kerberos.realm-trust.outgoing-kvno.column" }), "outgoingKvno"],
        [msg("Incoming KVNO", { id: "kerberos.realm-trust.incoming-kvno.column" }), "incomingKvno"],
        [
            msg("Actions", { id: "kerberos.realm-trust.actions.column" }),
            null,
            msg("Row actions", { id: "kerberos.realm-trust.actions.aria-label" }),
        ],
    ];

    protected override renderToolbarSelected(): SlottedTemplateResult {
        const disabled = this.selectedElements.length < 1;
        return html`<ak-forms-delete-bulk
            object-label=${msg("Realm trust(s)", {
                id: "kerberos.realm-trust.bulk-delete.object-label",
            })}
            .objects=${this.selectedElements}
            .metadata=${(item: KerberosRealmTrust) => [
                {
                    key: msg("Remote realm", { id: "kerberos.realm-trust.remote-realm.metadata" }),
                    value: item.remoteRealm,
                },
            ]}
            .delete=${(item: KerberosRealmTrust) =>
                aki(ProvidersApi).providersKerberosRealmTrustsDestroy({ uuid: item.uuid })}
        >
            <button ?disabled=${disabled} slot="trigger" class="pf-c-button pf-m-danger">
                ${msg("Delete", { id: "kerberos.realm-trust.delete.label" })}
            </button>
        </ak-forms-delete-bulk>`;
    }

    private async downloadKeytab(item: KerberosRealmTrust, direction: DirectionEnum): Promise<void> {
        const response = await aki(
            ProvidersApi,
        ).providersKerberosRealmTrustsKeytabRetrieveRaw({
            uuid: item.uuid,
            direction,
        });
        const payload: unknown = await response.raw.json();
        if (
            !payload ||
            typeof payload !== "object" ||
            !("keytab" in payload) ||
            typeof payload.keytab !== "string"
        ) {
            throw new Error("The keytab response did not contain a base64 keytab");
        }

        const bytes = Uint8Array.from(atob(payload.keytab), (character) => character.charCodeAt(0));
        downloadFile({
            content: bytes,
            filename: keytabFilename(item.remoteRealm, direction),
            type: "application/octet-stream",
        });
    }

    private rotate(item: KerberosRealmTrust, direction: DirectionEnum) {
        return aki(ProvidersApi).providersKerberosRealmTrustsRotateCreate({
            uuid: item.uuid,
            direction,
        });
    }

    protected override row(item: KerberosRealmTrust): SlottedTemplateResult[] {
        return [
            item.remoteRealm,
            item.capaths?.join(", ") || "-",
            item.outgoingKvno,
            item.incomingKvno,
            html`<div class="ak-c-table__actions">
                ${IconEditButton(RealmTrustForm, item.uuid)}
                ${([DirectionEnum.Outgoing, DirectionEnum.Incoming] as const).map((direction) => {
                    const text = directionText(direction);
                    return html`
                        <button
                            class="pf-c-button pf-m-plain"
                            type="button"
                            title=${text.download}
                            @click=${() => this.downloadKeytab(item, direction)}
                        >
                            <i class="fas fa-download" aria-hidden="true"></i>
                            <span class="sr-only">${text.download}</span>
                        </button>
                        <ak-forms-confirm
                            successMessage=${text.rotated}
                            errorMessage=${text.rotateError}
                            action=${msg("Rotate keys", {
                                id: "kerberos.realm-trust.rotate.action",
                            })}
                            .onConfirm=${() => this.rotate(item, direction)}
                        >
                            <span slot="header">${text.rotateTitle}</span>
                            <p slot="body">${text.confirmation}</p>
                            <button
                                slot="trigger"
                                class="pf-c-button pf-m-plain"
                                type="button"
                                title=${msg("Rotate keys", {
                                    id: "kerberos.realm-trust.rotate.tooltip",
                                })}
                            >
                                <i class="fas fa-sync" aria-hidden="true"></i>
                                <span class="sr-only"
                                    >${msg("Rotate keys", {
                                        id: "kerberos.realm-trust.rotate.label",
                                    })}</span
                                >
                            </button>
                        </ak-forms-confirm>
                    `;
                })}
            </div>`,
        ];
    }

    protected override renderObjectCreate(): SlottedTemplateResult {
        return ModalInvokerButton(RealmTrustForm, {
            providerID: this.provider?.pk,
        });
    }
}

declare global {
    interface HTMLElementTagNameMap {
        "ak-kerberos-realm-trust-list": RealmTrustList;
    }
}
