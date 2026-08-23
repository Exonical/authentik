import { APIError } from "#common/errors/network";
import { APIMessage, MessageLevel } from "#common/messages";

import { ModelForm } from "#elements/forms/ModelForm";

import { msg } from "@lit/localize";

/**
 * Placeholder for credentials the server generates when left empty on create.
 * Returns nothing for an existing provider, where a blank value is rejected.
 */
export function generatedPlaceholder(provider: { pk?: number }): string | undefined {
    return provider.pk
        ? undefined
        : msg("Generated automatically if left empty", {
              id: "forms.placeholder.generated-if-empty",
              desc: "Placeholder for a credential input which the server fills in when left empty.",
          });
}

/**
 * Base form for all provider forms.
 *
 * @prop {number} instancePk - The primary key of the instance to load.
 */
export abstract class BaseProviderForm<T extends object> extends ModelForm<T, number> {
    public static override verboseName = msg("Provider");
    public static override verboseNamePlural = msg("Providers");

    public override getSuccessMessage(): string {
        return this.instance
            ? msg("Successfully updated provider.")
            : msg("Successfully created provider.");
    }

    protected override formatAPIErrorMessage(error: APIError): APIMessage {
        return {
            level: MessageLevel.error,
            ...super.formatAPIErrorMessage(error),
            message: this.instance
                ? msg("An error occurred while updating the provider.")
                : msg("An error occurred while creating the provider."),
        };
    }
}
