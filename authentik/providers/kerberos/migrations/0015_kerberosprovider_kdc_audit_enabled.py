from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('authentik_providers_kerberos', '0014_kerberosprovider_kprop_client_spn_and_more'),
    ]

    operations = [
        migrations.AddField(
            model_name='kerberosprovider',
            name='kdc_audit_enabled',
            field=models.BooleanField(default=False, help_text='Emit authentik events for KDC ticket operations.'),
        ),
    ]
