import { renderForm } from "./KerberosProviderFormForm.js";

import { aki } from "#common/api/client";

import { BaseProviderForm } from "#admin/providers/BaseProviderForm";

import { KerberosProvider, ProvidersApi } from "@goauthentik/api";

import { customElement } from "lit/decorators.js";

@customElement("ak-provider-kerberos-form")
export class KerberosProviderFormPage extends BaseProviderForm<KerberosProvider> {
    protected endpoints = {
        load: (id: number) => aki(ProvidersApi).providersKerberosRetrieve({ id }),
        create: (kerberosProviderRequest: KerberosProvider) =>
            aki(ProvidersApi).providersKerberosCreate({ kerberosProviderRequest }),
        update: (id: number, kerberosProviderRequest: KerberosProvider) =>
            aki(ProvidersApi).providersKerberosUpdate({ id, kerberosProviderRequest }),
    };

    renderForm() {
        return renderForm({ provider: this.instance });
    }
}

declare global {
    interface HTMLElementTagNameMap {
        "ak-provider-kerberos-form": KerberosProviderFormPage;
    }
}
