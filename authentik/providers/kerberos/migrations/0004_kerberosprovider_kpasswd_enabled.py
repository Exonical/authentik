from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('authentik_providers_kerberos', '0003_kerberosprovider_pkinit_certificate_and_more'),
    ]

    operations = [
        migrations.AddField(
            model_name='kerberosprovider',
            name='kpasswd_enabled',
            field=models.BooleanField(default=True, help_text='Enable RFC 3244 password changes through the Kerberos outpost.'),
        ),
    ]
