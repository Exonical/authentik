import "#admin/providers/kerberos/ServicePrincipalForm";
import "#elements/forms/ConfirmationForm";
import "#elements/forms/DeleteBulkForm";
import "#elements/forms/ModalForm";

import { aki } from "#common/api/client";
import { downloadFile } from "#common/download";

import { IconEditButton, ModalInvokerButton } from "#elements/dialogs";
import { PaginatedResponse, Table, TableColumn } from "#elements/table/Table";
import { SlottedTemplateResult } from "#elements/types";

import { ServicePrincipalForm } from "#admin/providers/kerberos/ServicePrincipalForm";

import {
    CoreApi,
    KerberosProvider,
    KerberosServicePrincipal,
    ProvidersApi,
} from "@goauthentik/api";

import { msg } from "@lit/localize";
import { CSSResult, html } from "lit";
import { customElement, property, state } from "lit/decorators.js";

import PFDescriptionList from "@patternfly/patternfly/components/DescriptionList/description-list.css";

function servicePrincipalRequest(item: KerberosServicePrincipal) {
    return {
        provider: item.provider,
        spn: item.spn,
        serviceAccount: item.serviceAccount,
        okToAuthAsDelegate: item.okToAuthAsDelegate,
        allowedDelegationTargets: item.allowedDelegationTargets,
    };
}

function keytabFilename(spn: string): string {
    const safeName = spn.replace(/[^a-zA-Z0-9._-]+/g, "_");
    return `${safeName || "service-principal"}.keytab`;
}

@customElement("ak-kerberos-service-principal-list")
export class ServicePrincipalList extends Table<KerberosServicePrincipal> {
    public static styles: CSSResult[] = [...super.styles, PFDescriptionList];

    public static override verboseName = msg("Service principal", {
        id: "kerberos.service-principal.verbose-name",
    });
    public static override verboseNamePlural = msg("Service principals", {
        id: "kerberos.service-principal.verbose-name-plural",
    });

    protected override searchEnabled = true;
    protected override emptyStateMessage = msg("Create a service principal to get started.", {
        id: "kerberos.service-principal.empty-state",
    });

    public override checkbox = true;
    public override clearOnRefresh = true;
    public override searchPlaceholder = msg("Search for a service principal...", {
        id: "kerberos.service-principal.search.placeholder",
    });
    public override order = "spn";

    @property({ attribute: false })
    public provider: KerberosProvider | null = null;

    @state()
    private serviceAccountNames = new Map<number, string>();

    protected override async apiEndpoint(): Promise<PaginatedResponse<KerberosServicePrincipal>> {
        const response = await aki(ProvidersApi).providersKerberosServicePrincipalsList({
            ...(await this.defaultEndpointConfig()),
            provider: this.provider?.pk,
        });

        const serviceAccountIds = response.results
            .map((item) => item.serviceAccount)
            .filter((id): id is number => id !== undefined && id !== null);
        const names = await Promise.all(
            serviceAccountIds.map(async (id) => {
                try {
                    const user = await aki(CoreApi).coreUsersRetrieve({ id });
                    return [id, user.username] as const;
                } catch {
                    return null;
                }
            }),
        );
        this.serviceAccountNames = new Map(
            names.filter((entry): entry is readonly [number, string] => entry !== null),
        );

        return response;
    }

    protected override columns: TableColumn[] = [
        [msg("SPN", { id: "kerberos.service-principal.spn.column" }), "spn"],
        [msg("KVNO", { id: "kerberos.service-principal.kvno.column" }), "kvno"],
        [
            msg("Service account", {
                id: "kerberos.service-principal.service-account.column",
            }),
            "serviceAccount",
        ],
        [
            msg("Delegation", { id: "kerberos.service-principal.delegation.column" }),
            "okToAuthAsDelegate",
        ],
        [
            msg("Actions", { id: "kerberos.service-principal.actions.column" }),
            null,
            msg("Row actions", { id: "kerberos.service-principal.actions.aria-label" }),
        ],
    ];

    protected override renderToolbarSelected(): SlottedTemplateResult {
        const disabled = this.selectedElements.length < 1;
        return html`<ak-forms-delete-bulk
            object-label=${msg("Service principal(s)", {
                id: "kerberos.service-principal.bulk-delete.object-label",
            })}
            .objects=${this.selectedElements}
            .metadata=${(item: KerberosServicePrincipal) => [
                {
                    key: msg("SPN", { id: "kerberos.service-principal.spn.metadata" }),
                    value: item.spn,
                },
            ]}
            .delete=${(item: KerberosServicePrincipal) =>
                aki(ProvidersApi).providersKerberosServicePrincipalsDestroy({
                    uuid: item.uuid,
                })}
        >
            <button ?disabled=${disabled} slot="trigger" class="pf-c-button pf-m-danger">
                ${msg("Delete", { id: "kerberos.service-principal.delete.label" })}
            </button>
        </ak-forms-delete-bulk>`;
    }

    private async downloadKeytab(item: KerberosServicePrincipal): Promise<void> {
        const response = await aki(
            ProvidersApi,
        ).providersKerberosServicePrincipalsKeytabRetrieveRaw({ uuid: item.uuid });
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
            filename: keytabFilename(item.spn),
            type: "application/octet-stream",
        });
    }

    protected override row(item: KerberosServicePrincipal): SlottedTemplateResult[] {
        const targetCount = item.allowedDelegationTargets?.length ?? 0;
        return [
            item.spn,
            item.kvno,
            item.serviceAccount ? (this.serviceAccountNames.get(item.serviceAccount) ?? "-") : "-",
            html`${item.okToAuthAsDelegate
                ? msg("Yes", { id: "kerberos.service-principal.delegation.yes" })
                : msg("No", { id: "kerberos.service-principal.delegation.no" })}
            (${targetCount})`,
            html`<div class="ak-c-table__actions">
                ${IconEditButton(ServicePrincipalForm, item.uuid)}
                <button
                    class="pf-c-button pf-m-plain"
                    type="button"
                    title=${msg("Download keytab", {
                        id: "kerberos.service-principal.download-keytab.tooltip",
                    })}
                    @click=${() => this.downloadKeytab(item)}
                >
                    <i class="fas fa-download" aria-hidden="true"></i>
                    <span class="sr-only"
                        >${msg("Download keytab", {
                            id: "kerberos.service-principal.download-keytab.label",
                        })}</span
                    >
                </button>
                <ak-forms-confirm
                    successMessage=${msg("Successfully rotated service principal keys.", {
                        id: "kerberos.service-principal.rotate.success",
                    })}
                    errorMessage=${msg("Failed to rotate service principal keys.", {
                        id: "kerberos.service-principal.rotate.error",
                    })}
                    action=${msg("Rotate keys", {
                        id: "kerberos.service-principal.rotate.action",
                    })}
                    .onConfirm=${() =>
                        aki(ProvidersApi).providersKerberosServicePrincipalsRotateCreate({
                            uuid: item.uuid,
                            kerberosServicePrincipalRequest: servicePrincipalRequest(item),
                        })}
                >
                    <span slot="header"
                        >${msg("Rotate service principal keys", {
                            id: "kerberos.service-principal.rotate.title",
                        })}</span
                    >
                    <p slot="body">
                        ${msg("Are you sure you want to rotate this service principal's keys?", {
                            id: "kerberos.service-principal.rotate.confirmation",
                        })}
                    </p>
                    <button
                        slot="trigger"
                        class="pf-c-button pf-m-plain"
                        type="button"
                        title=${msg("Rotate keys", {
                            id: "kerberos.service-principal.rotate.tooltip",
                        })}
                    >
                        <i class="fas fa-sync" aria-hidden="true"></i>
                        <span class="sr-only"
                            >${msg("Rotate keys", {
                                id: "kerberos.service-principal.rotate.label",
                            })}</span
                        >
                    </button>
                </ak-forms-confirm>
            </div>`,
        ];
    }

    protected override renderObjectCreate(): SlottedTemplateResult {
        return ModalInvokerButton(ServicePrincipalForm, {
            providerID: this.provider?.pk,
        });
    }
}

declare global {
    interface HTMLElementTagNameMap {
        "ak-kerberos-service-principal-list": ServicePrincipalList;
    }
}
