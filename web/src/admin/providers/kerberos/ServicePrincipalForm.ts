import "#components/ak-switch-input";
import "#components/ak-text-input";
import "#elements/ak-array-input";
import "#elements/ak-checkbox-group/ak-checkbox-group";
import "#elements/forms/HorizontalFormElement";
import "#elements/forms/SearchSelect/index";

import { aki } from "#common/api/client";

import { CheckboxPair } from "#elements/ak-checkbox-group/ak-checkbox-group";
import { ModelForm } from "#elements/forms/ModelForm";
import { SlottedTemplateResult } from "#elements/types";

import {
    CoreApi,
    CoreUsersListRequest,
    KerberosServicePrincipal,
    KerberosServicePrincipalRequest,
    ProvidersApi,
    User,
} from "@goauthentik/api";

import { msg } from "@lit/localize";
import { html, TemplateResult } from "lit";
import { customElement, property } from "lit/decorators.js";
import { ifDefined } from "lit/directives/if-defined.js";

@customElement("ak-kerberos-service-principal-form")
export class ServicePrincipalForm extends ModelForm<
    KerberosServicePrincipal,
    string,
    KerberosServicePrincipalRequest
> {
    public static override verboseName = msg("Service principal", {
        id: "kerberos.service-principal.verbose-name",
    });
    public static override verboseNamePlural = msg("Service principals", {
        id: "kerberos.service-principal.verbose-name-plural",
    });

    @property({ type: Number })
    public providerID: number | null = null;

    protected override loadInstance(pk: string): Promise<KerberosServicePrincipal> {
        return aki(ProvidersApi).providersKerberosServicePrincipalsRetrieve({
            uuid: pk,
        });
    }

    public override getSuccessMessage(): string {
        return this.instance
            ? msg("Successfully updated service principal.", {
                  id: "kerberos.service-principal.update.success",
              })
            : msg("Successfully created service principal.", {
                  id: "kerberos.service-principal.create.success",
              });
    }

    public override async send(
        data: KerberosServicePrincipalRequest,
    ): Promise<KerberosServicePrincipal> {
        data.serviceAccount ??= null;
        if (!this.instance) {
            data.provider = this.providerID || 0;
        } else {
            data.provider = this.instance.provider;
        }

        if (this.instance) {
            return aki(ProvidersApi).providersKerberosServicePrincipalsPartialUpdate({
                uuid: this.instance.uuid,
                patchedKerberosServicePrincipalRequest: data,
            });
        }
        return aki(ProvidersApi).providersKerberosServicePrincipalsCreate({
            kerberosServicePrincipalRequest: data,
        });
    }

    protected override renderForm(): SlottedTemplateResult {
        const ticketFlags: CheckboxPair[] = [
            ["requires_preauth", msg("Requires preauthentication", {
                id: "kerberos.service-principal.ticket-flags.requires-preauth",
            })],
            ["requires_hwauth", msg("Requires hardware authentication", {
                id: "kerberos.service-principal.ticket-flags.requires-hwauth",
            })],
            ["disallow_postdated", msg("Disallow postdated tickets", {
                id: "kerberos.service-principal.ticket-flags.disallow-postdated",
            })],
            ["disallow_forwardable", msg("Disallow forwardable tickets", {
                id: "kerberos.service-principal.ticket-flags.disallow-forwardable",
            })],
            ["disallow_proxiable", msg("Disallow proxiable tickets", {
                id: "kerberos.service-principal.ticket-flags.disallow-proxiable",
            })],
            ["disallow_renewable", msg("Disallow renewable tickets", {
                id: "kerberos.service-principal.ticket-flags.disallow-renewable",
            })],
            ["disallow_tgt_based", msg("Disallow TGT-based tickets", {
                id: "kerberos.service-principal.ticket-flags.disallow-tgt-based",
            })],
            ["disallow_server", msg("Disallow service tickets", {
                id: "kerberos.service-principal.ticket-flags.disallow-server",
            })],
        ];
        return html`
            <ak-text-input
                label=${msg("SPN", { id: "kerberos.service-principal.spn.label" })}
                name="spn"
                required
                value="${ifDefined(this.instance?.spn)}"
                placeholder=${msg("service/hostname", {
                    id: "kerberos.service-principal.spn.placeholder",
                })}
                input-hint="code"
                help=${msg("The Kerberos service principal name, for example service/hostname.", {
                    id: "kerberos.service-principal.spn.help",
                })}
                autofocus
            ></ak-text-input>

            <ak-form-element-horizontal
                label=${msg("Service account", {
                    id: "kerberos.service-principal.service-account.label",
                })}
                name="serviceAccount"
            >
                <ak-search-select
                    .fetchObjects=${async (query?: string): Promise<User[]> => {
                        const args: CoreUsersListRequest = {
                            ordering: "username",
                        };
                        if (query !== undefined) {
                            args.search = query;
                        }
                        const users = await aki(CoreApi).coreUsersList(args);
                        return users.results;
                    }}
                    .renderElement=${(user: User): string => user.username}
                    .renderDescription=${(user: User): TemplateResult => html`${user.name}`}
                    .value=${(user: User | undefined): number | undefined => user?.pk}
                    .selected=${(user: User): boolean => user.pk === this.instance?.serviceAccount}
                    blankable
                ></ak-search-select>
                <p class="pf-c-form__helper-text">
                    ${msg(
                        "Optional authentik user whose policies apply when this principal acts as a Kerberos client.",
                        { id: "kerberos.service-principal.service-account.help" },
                    )}
                </p>
            </ak-form-element-horizontal>

            <ak-form-element-horizontal
                label=${msg("Ticket flags", {
                    id: "kerberos.service-principal.ticket-flags.label",
                })}
                name="ticketFlags"
            >
                <ak-checkbox-group
                    name="ticketFlags"
                    .options=${ticketFlags}
                    .value=${this.instance?.ticketFlags ?? []}
                ></ak-checkbox-group>
                <p class="pf-c-form__helper-text">
                    ${msg("Kerberos ticket flags applied to this service principal.", {
                        id: "kerberos.service-principal.ticket-flags.help",
                    })}
                </p>
            </ak-form-element-horizontal>

            <ak-form-element-horizontal
                label=${msg("Required authentication indicators", {
                    id: "kerberos.service-principal.required-auth-indicators.label",
                })}
                name="requiredAuthIndicators"
            >
                <ak-array-input
                    name="required-auth-indicator"
                    .items=${this.instance?.requiredAuthIndicators ?? []}
                    .newItem=${() => ""}
                    .row=${(indicator: string) => html`
                        <ak-text-input
                            name="indicator"
                            value="${indicator}"
                            placeholder=${msg("indicator", {
                                id: "kerberos.service-principal.required-auth-indicators.placeholder",
                            })}
                            input-hint="code"
                        ></ak-text-input>
                    `}
                ></ak-array-input>
                <p class="pf-c-form__helper-text">
                    ${msg(
                        "Any one of these indicators must be present to obtain tickets for this service.",
                        { id: "kerberos.service-principal.required-auth-indicators.help" },
                    )}
                </p>
            </ak-form-element-horizontal>

            <ak-switch-input
                name="okToAuthAsDelegate"
                label=${msg("Allow delegation", {
                    id: "kerberos.service-principal.delegation.label",
                })}
                ?checked=${this.instance?.okToAuthAsDelegate ?? false}
                help=${msg(
                    "Allow this service principal to authenticate as a user for delegation.",
                    {
                        id: "kerberos.service-principal.delegation.help",
                    },
                )}
            ></ak-switch-input>

            <ak-form-element-horizontal
                label=${msg("Allowed delegation targets", {
                    id: "kerberos.service-principal.allowed-targets.label",
                })}
                name="allowedDelegationTargets"
            >
                <ak-array-input
                    name="allowed-delegation-target"
                    .items=${this.instance?.allowedDelegationTargets ?? []}
                    .newItem=${() => ""}
                    .row=${(target: string) => html`
                        <ak-text-input
                            name="target"
                            value="${target}"
                            placeholder=${msg("service/hostname", {
                                id: "kerberos.service-principal.allowed-targets.placeholder",
                            })}
                            input-hint="code"
                        ></ak-text-input>
                    `}
                ></ak-array-input>
                <p class="pf-c-form__helper-text">
                    ${msg(
                        "Service principals this principal may request tickets for when delegation is enabled.",
                        { id: "kerberos.service-principal.allowed-targets.help" },
                    )}
                </p>
            </ak-form-element-horizontal>
        `;
    }
}

declare global {
    interface HTMLElementTagNameMap {
        "ak-kerberos-service-principal-form": ServicePrincipalForm;
    }
}
