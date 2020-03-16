# Generated by Django 2.2.10 on 2020-03-06 17:02

from django.db import migrations, models
import django.db.models.deletion

from device_registry.models import DEBIAN_SUITES, UBUNTU_SUITES, DEBIAN_KERNEL_PACKAGES_RE_PATTERN
from device_registry.models import UBUNTU_KERNEL_PACKAGES_RE_PATTERN


def reset_kernel_packages_vulns(apps, schema_editor):
    # Delete vulns of kernel-related packages.
    DebPackageVulnerability = apps.get_model('device_registry', 'DebPackage').vulnerabilities.through
    # Debian.
    DebPackageVulnerability.objects.filter(
        debpackage__os_release_codename__in=DEBIAN_SUITES, debpackage__name__regex=DEBIAN_KERNEL_PACKAGES_RE_PATTERN
    ).delete()
    # Ubuntu.
    DebPackageVulnerability.objects.filter(
        debpackage__os_release_codename__in=UBUNTU_SUITES, debpackage__name__regex=UBUNTU_KERNEL_PACKAGES_RE_PATTERN
    ).delete()


class Migration(migrations.Migration):

    dependencies = [
        ('device_registry', '0085_auto_20200302_1420'),
    ]

    operations = [
        migrations.AddField(
            model_name='device',
            name='kernel_meta_package',
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='+', to='device_registry.DebPackage'),
        ),
        migrations.AddField(
            model_name='device',
            name='reboot_required',
            field=models.BooleanField(blank=True, db_index=True, null=True),
        ),
        migrations.AlterField(
            model_name='vulnerability',
            name='name',
            field=models.CharField(db_index=True, max_length=64),
        ),
        migrations.AlterField(
            model_name='vulnerability',
            name='fix_available',
            field=models.BooleanField(db_index=True),
        ),
        migrations.RunPython(reset_kernel_packages_vulns)
    ]
