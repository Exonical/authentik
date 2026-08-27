import "#components/ak-text-input";
import "#elements/forms/FormGroup";
import "#elements/forms/HorizontalFormElement";
import "#elements/utils/TimeDeltaHelp";

import { KerberosProvider, ValidationError } from "@goauthentik/api";

import { msg } from "@lit/localize";
import { html } from "lit";
import { ifDefined } from "lit/directives/if-defined.js";

const ENCTYPE_OPTIONS = [
    [17, "aes128-cts-hmac-sha1-96"],
    [18, "aes256-cts-hmac-sha1-96"],
    [19, "aes128-cts-hmac-sha256-128"],
    [20, "aes256-cts-hmac-sha384-192"],
] as const;

export interface KerberosProviderFormProps {
    provider?: Partial<KerberosProvider> | null;
    errors?: ValidationError | null;
}

export function renderForm({ provider, errors }: KerberosProviderFormProps) {
    provider ||= {};
    const allowedEnctypes = provider.allowedEnctypes ?? [18, 20];

    return html`
        <ak-text-input
            name="name"
            value=${ifDefined(provider.name)}
            label=${msg("Provider Name", { id: "kerberos.provider-name.label" })}
            placeholder=${msg("Type a provider name...", {
                id: "kerberos.provider-name.placeholder",
            })}
            .errorMessages=${errors?.name}
            required
        ></ak-text-input>

        <ak-text-input
            name="realmName"
            value=${ifDefined(provider.realmName)}
            label=${msg("Realm", { id: "kerberos.realm-name.label" })}
            placeholder=${msg("EXAMPLE.COM", { id: "kerberos.realm-name.placeholder" })}
            .errorMessages=${errors?.realmName}
            input-hint="code"
            required
        ></ak-text-input>

        <ak-form-group
            open
            label=${msg("Ticket settings", { id: "kerberos.ticket-settings.label" })}
        >
            <div class="pf-c-form">
                <ak-form-element-horizontal
                    label=${msg("Maximum ticket lifetime", {
                        id: "kerberos.ticket-lifetime.label",
                    })}
                    name="maximumTicketLifetime"
                    .errorMessages=${errors?.maximumTicketLifetime}
                    required
                >
                    <input
                        class="pf-c-form-control pf-m-monospace"
                        name="maximumTicketLifetime"
                        value=${provider.maximumTicketLifetime ?? "hours=10"}
                        autocomplete="off"
                        spellcheck="false"
                        required
                    />
                    <p class="pf-c-form__helper-text">
                        ${msg("Maximum lifetime of an issued ticket.", {
                            id: "kerberos.ticket-lifetime.help",
                        })}
                    </p>
                    <ak-utils-time-delta-help></ak-utils-time-delta-help>
                </ak-form-element-horizontal>

                <ak-form-element-horizontal
                    label=${msg("Maximum ticket renew lifetime", {
                        id: "kerberos.ticket-renew-lifetime.label",
                    })}
                    name="maximumTicketRenewLifetime"
                    .errorMessages=${errors?.maximumTicketRenewLifetime}
                    required
                >
                    <input
                        class="pf-c-form-control pf-m-monospace"
                        name="maximumTicketRenewLifetime"
                        value=${provider.maximumTicketRenewLifetime ?? "days=7"}
                        autocomplete="off"
                        spellcheck="false"
                        required
                    />
                    <p class="pf-c-form__helper-text">
                        ${msg("Maximum lifetime for ticket renewal.", {
                            id: "kerberos.ticket-renew-lifetime.help",
                        })}
                    </p>
                    <ak-utils-time-delta-help></ak-utils-time-delta-help>
                </ak-form-element-horizontal>
            </div>
        </ak-form-group>

        <ak-form-element-horizontal
            label=${msg("Allowed encryption types", { id: "kerberos.allowed-enctypes.label" })}
            name="allowedEnctypes"
            .errorMessages=${errors?.allowedEnctypes}
            required
        >
            <select class="pf-c-form-control" name="allowedEnctypes" multiple required>
                ${ENCTYPE_OPTIONS.map(
                    ([value, label]) => html`
                        <option value=${value} ?selected=${allowedEnctypes.includes(value)}>
                            ${label}
                        </option>
                    `,
                )}
            </select>
            <p class="pf-c-form__helper-text">
                ${msg("Encryption types accepted by the KDC.", {
                    id: "kerberos.allowed-enctypes.help",
                })}
            </p>
        </ak-form-element-horizontal>
    `;
}
