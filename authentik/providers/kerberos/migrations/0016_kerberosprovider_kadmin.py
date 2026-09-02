from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("authentik_providers_kerberos", "0015_kerberosprovider_kdc_audit_enabled"),
    ]

    operations = [
        migrations.AddField(
            model_name="kerberosprovider",
            name="kadmin_enabled",
            field=models.BooleanField(
                default=False,
                help_text="Serve the kadm5 admin protocol from the outpost.",
            ),
        ),
        migrations.AddField(
            model_name="kerberosprovider",
            name="kadmin_acl",
            field=models.JSONField(
                blank=True,
                default=list,
                help_text="MIT kadm5 ACL entries controlling administrative access.",
            ),
        ),
    ]
