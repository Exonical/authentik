import "#elements/ak-array-input";
import "#components/ak-text-input";

import { aki } from "#common/api/client";

import { ModelForm } from "#elements/forms/ModelForm";
import { SlottedTemplateResult } from "#elements/types";

import {
    KerberosRealmTrust,
    KerberosRealmTrustRequest,
    ProvidersApi,
} from "@goauthentik/api";

import { msg } from "@lit/localize";
import { html } from "lit";
import { customElement, property } from "lit/decorators.js";
import { ifDefined } from "lit/directives/if-defined.js";

@customElement("ak-kerberos-realm-trust-form")
export class RealmTrustForm extends ModelForm<KerberosRealmTrust, string, KerberosRealmTrustRequest> {
    public static override verboseName = msg("Realm trust", {
        id: "kerberos.realm-trust.verbose-name",
    });
    public static override verboseNamePlural = msg("Realm trusts", {
        id: "kerberos.realm-trust.verbose-name-plural",
    });

    @property({ type: Number })
    public providerID: number | null = null;

    protected override loadInstance(pk: string): Promise<KerberosRealmTrust> {
        return aki(ProvidersApi).providersKerberosRealmTrustsRetrieve({ uuid: pk });
    }

    public override getSuccessMessage(): string {
        return this.instance
            ? msg("Successfully updated realm trust.", {
                  id: "kerberos.realm-trust.update.success",
              })
            : msg("Successfully created realm trust.", {
                  id: "kerberos.realm-trust.create.success",
              });
    }

    public override async send(data: KerberosRealmTrustRequest): Promise<KerberosRealmTrust> {
        if (!this.instance) {
            data.provider = this.providerID || 0;
        } else {
            data.provider = this.instance.provider;
        }

        if (this.instance) {
            return aki(ProvidersApi).providersKerberosRealmTrustsPartialUpdate({
                uuid: this.instance.uuid,
                patchedKerberosRealmTrustRequest: data,
            });
        }
        return aki(ProvidersApi).providersKerberosRealmTrustsCreate({
            kerberosRealmTrustRequest: data,
        });
    }

    protected override renderForm(): SlottedTemplateResult {
        return html`
            <ak-text-input
                label=${msg("Remote realm", { id: "kerberos.realm-trust.remote-realm.label" })}
                name="remoteRealm"
                required
                value="${ifDefined(this.instance?.remoteRealm)}"
                placeholder="REMOTE.EXAMPLE"
                input-hint="code"
                help=${msg("The realm name of the remote Kerberos realm.", {
                    id: "kerberos.realm-trust.remote-realm.help",
                })}
                autofocus
            ></ak-text-input>

            <ak-form-element-horizontal
                label=${msg("Intermediate realms", {
                    id: "kerberos.realm-trust.capaths.label",
                })}
                name="capaths"
            >
                <ak-array-input
                    name="capath"
                    .items=${this.instance?.capaths ?? []}
                    .newItem=${() => ""}
                    .row=${(realm: string) => html`
                        <ak-text-input
                            name="realm"
                            value="${realm}"
                            placeholder="INTERMEDIATE.EXAMPLE"
                            input-hint="code"
                        ></ak-text-input>
                    `}
                ></ak-array-input>
                <p class="pf-c-form__helper-text">
                    ${msg(
                        "Intermediate realms used for transited-path checking between the local and remote realms.",
                        { id: "kerberos.realm-trust.capaths.help" },
                    )}
                </p>
            </ak-form-element-horizontal>
        `;
    }
}

declare global {
    interface HTMLElementTagNameMap {
        "ak-kerberos-realm-trust-form": RealmTrustForm;
    }
}
