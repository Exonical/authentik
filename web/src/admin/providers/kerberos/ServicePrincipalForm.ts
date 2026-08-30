import "#components/ak-switch-input";
import "#components/ak-text-input";
import "#elements/ak-array-input";
import "#elements/forms/HorizontalFormElement";
import "#elements/forms/SearchSelect/index";

import { aki } from "#common/api/client";

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
