# Generated by Django 2.2.24 on 2023-11-28 13:35

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('eol_sso_login', '0002_auto_20231121_2022'),
    ]

    operations = [
        migrations.AlterField(
            model_name='ssologinextradata',
            name='document',
            field=models.CharField(help_text='Document number', max_length=21, verbose_name='Document'),
        ),
        # migrations.AlterField(
        #     model_name='ssologinextradata',
        #     name='type_document',
        #     field=models.TextField(choices=[('rut', 'Rut'), ('passport', 'Passport'), ('dni', 'DNI')], help_text='Select document type', max_length=10, verbose_name='Document type'),
        # ),
    ]
