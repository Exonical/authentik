import "#admin/common/ak-flow-search/ak-flow-search";
import "#admin/common/ak-flow-search/ak-branded-flow-search";
import "#components/ak-switch-input";
import "#components/ak-text-input";
import "#elements/forms/FormGroup";
import "#elements/forms/HorizontalFormElement";
import "#elements/utils/TimeDeltaHelp";

import {
    CurrentBrand,
    FlowDesignationEnum,
    KerberosProvider,
    ValidationError,
} from "@goauthentik/api";

import { msg } from "@lit/localize";
import { html } from "lit";
import { ifDefined } from "lit/directives/if-defined.js";

export const ENCTYPE_OPTIONS = [
    [17, "aes128-cts-hmac-sha1-96"],
    [18, "aes256-cts-hmac-sha1-96"],
    [19, "aes128-cts-hmac-sha256-128"],
    [20, "aes256-cts-hmac-sha384-192"],
] as const;

export function enctypeName(enctype: number): string {
    return ENCTYPE_OPTIONS.find(([value]) => value === enctype)?.[1] ?? String(enctype);
}

export interface KerberosProviderFormProps {
    provider?: Partial<KerberosProvider> | null;
    errors?: ValidationError | null;
    brand?: CurrentBrand | null;
}

export function renderForm({ provider, errors, brand }: KerberosProviderFormProps) {
    provider ||= {};
    errors ||= {};
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

        <ak-form-group open label=${msg("Flow settings", { id: "kerberos.flow-settings.label" })}>
            <div class="pf-c-form">
                <ak-form-element-horizontal
                    label=${msg("Authentication flow", {
                        id: "kerberos.authentication-flow.label",
                    })}
                    name="authenticationFlow"
                    .errorMessages=${errors.authenticationFlow}
                >
                    <ak-branded-flow-search
                        label=${msg("Authentication flow", {
                            id: "kerberos.authentication-flow.search-label",
                        })}
                        placeholder=${msg("Select an authentication flow...", {
                            id: "kerberos.authentication-flow.placeholder",
                        })}
                        flowType=${FlowDesignationEnum.Authentication}
                        .currentFlow=${provider.authenticationFlow}
                        .brandFlow=${brand?.flowAuthentication}
                        required
                    ></ak-branded-flow-search>
                </ak-form-element-horizontal>
                <ak-form-element-horizontal
                    label=${msg("Authorization flow", {
                        id: "kerberos.authorization-flow.label",
                    })}
                    name="authorizationFlow"
                    .errorMessages=${errors.authorizationFlow}
                >
                    <ak-flow-search
                        label=${msg("Authorization flow", {
                            id: "kerberos.authorization-flow.search-label",
                        })}
                        placeholder=${msg("Select an authorization flow...", {
                            id: "kerberos.authorization-flow.placeholder",
                        })}
                        flowType=${FlowDesignationEnum.Authorization}
                        .currentFlow=${provider.authorizationFlow}
                        required
                    ></ak-flow-search>
                </ak-form-element-horizontal>
            </div>
        </ak-form-group>

        <ak-text-input
            name="realmName"
            value=${ifDefined(provider.realmName)}
            label=${msg("Realm", { id: "kerberos.realm-name.label" })}
            placeholder=${msg("EXAMPLE.COM", { id: "kerberos.realm-name.placeholder" })}
            .errorMessages=${errors?.realmName}
            input-hint="code"
            required
        ></ak-text-input>

        <ak-text-input
            name="defaultDomain"
            value=${ifDefined(provider.defaultDomain)}
            label=${msg("Default domain", { id: "kerberos.default-domain.label" })}
            placeholder=${msg("example.com", { id: "kerberos.default-domain.placeholder" })}
            .errorMessages=${errors.defaultDomain}
            input-hint="code"
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
                <ak-form-element-horizontal
                    label=${msg("Default ticket lifetime", {
                        id: "kerberos.default-ticket-lifetime.label",
                    })}
                    name="defaultTicketLifetime"
                    .errorMessages=${errors.defaultTicketLifetime}
                    required
                >
                    <input
                        class="pf-c-form-control pf-m-monospace"
                        name="defaultTicketLifetime"
                        value=${provider.defaultTicketLifetime ?? "hours=10"}
                        autocomplete="off"
                        spellcheck="false"
                        required
                    />
                    <p class="pf-c-form__helper-text">
                        ${msg("Default lifetime when a client does not request one.", {
                            id: "kerberos.default-ticket-lifetime.help",
                        })}
                    </p>
                    <ak-utils-time-delta-help></ak-utils-time-delta-help>
                </ak-form-element-horizontal>
                <ak-form-element-horizontal
                    label=${msg("Default ticket renew lifetime", {
                        id: "kerberos.default-ticket-renew-lifetime.label",
                    })}
                    name="defaultTicketRenewLifetime"
                    .errorMessages=${errors.defaultTicketRenewLifetime}
                    required
                >
                    <input
                        class="pf-c-form-control pf-m-monospace"
                        name="defaultTicketRenewLifetime"
                        value=${provider.defaultTicketRenewLifetime ?? "days=7"}
                        autocomplete="off"
                        spellcheck="false"
                        required
                    />
                    <p class="pf-c-form__helper-text">
                        ${msg("Default lifetime for ticket renewal.", {
                            id: "kerberos.default-ticket-renew-lifetime.help",
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

        <ak-form-group
            open
            label=${msg("Network settings", { id: "kerberos.network-settings.label" })}
        >
            <div class="pf-c-form">
                <ak-switch-input
                    name="udpEnabled"
                    label=${msg("UDP enabled", { id: "kerberos.udp-enabled.label" })}
                    ?checked=${provider.udpEnabled ?? true}
                ></ak-switch-input>
                <ak-switch-input
                    name="tcpEnabled"
                    label=${msg("TCP enabled", { id: "kerberos.tcp-enabled.label" })}
                    ?checked=${provider.tcpEnabled ?? true}
                ></ak-switch-input>
            </div>
        </ak-form-group>

        <ak-form-group
            open
            label=${msg("Policy settings", { id: "kerberos.policy-settings.label" })}
        >
            <div class="pf-c-form">
                <ak-switch-input
                    name="requirePreauthentication"
                    label=${msg("Require preauthentication", {
                        id: "kerberos.require-preauthentication.label",
                    })}
                    ?checked=${provider.requirePreauthentication ?? true}
                ></ak-switch-input>
                <ak-switch-input
                    name="forwardable"
                    label=${msg("Forwardable", { id: "kerberos.forwardable.label" })}
                    ?checked=${provider.forwardable ?? true}
                ></ak-switch-input>
                <ak-switch-input
                    name="renewable"
                    label=${msg("Renewable", { id: "kerberos.renewable.label" })}
                    ?checked=${provider.renewable ?? true}
                ></ak-switch-input>
                <ak-switch-input
                    name="proxiable"
                    label=${msg("Proxiable", { id: "kerberos.proxiable.label" })}
                    ?checked=${provider.proxiable ?? false}
                ></ak-switch-input>
            </div>
        </ak-form-group>

        <ak-form-group
            open
            label=${msg("Principal mapping", { id: "kerberos.principal-mapping.label" })}
        >
            <div class="pf-c-form">
                <ak-form-element-horizontal
                    label=${msg("Principal username attribute", {
                        id: "kerberos.principal-username-attribute.label",
                    })}
                    name="principalUsernameAttribute"
                    .errorMessages=${errors.principalUsernameAttribute}
                    required
                >
                    <select class="pf-c-form-control" name="principalUsernameAttribute" required>
                        <option
                            value="username"
                            ?selected=${(provider.principalUsernameAttribute ?? "username") ===
                            "username"}
                        >
                            ${msg("Username", {
                                id: "kerberos.principal-username-attribute.username",
                            })}
                        </option>
                        <option
                            value="email"
                            ?selected=${provider.principalUsernameAttribute === "email"}
                        >
                            ${msg("Email", { id: "kerberos.principal-username-attribute.email" })}
                        </option>
                        <option
                            value="upn"
                            ?selected=${provider.principalUsernameAttribute === "upn"}
                        >
                            ${msg("UPN", { id: "kerberos.principal-username-attribute.upn" })}
                        </option>
                    </select>
                </ak-form-element-horizontal>
            </div>
        </ak-form-group>
    `;
}
