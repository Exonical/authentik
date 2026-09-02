from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('authentik_providers_kerberos', '0012_kerberosrealmtrust'),
    ]

    operations = [
        migrations.AddField(
            model_name='kerberosserviceprincipal',
            name='ticket_flags',
            field=models.JSONField(blank=True, default=list, help_text='Ticket flags applied to this service principal.'),
        ),
    ]
