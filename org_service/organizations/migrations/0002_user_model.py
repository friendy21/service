# Generated migration for enhanced user model

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('organizations', '0001_initial'),
    ]

    operations = [
        migrations.AddField(
            model_name='orguser',
            name='password',
            field=models.CharField(blank=True, max_length=128, null=True),
        ),
        migrations.AddField(
            model_name='orguser',
            name='is_active',
            field=models.BooleanField(default=True),
        ),
        migrations.AddField(
            model_name='orguser',
            name='is_verified',
            field=models.BooleanField(default=False),
        ),
        migrations.AddField(
            model_name='orguser',
            name='last_login',
            field=models.DateTimeField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name='orguser',
            name='password_changed_at',
            field=models.DateTimeField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name='orguser',
            name='created_by',
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='created_users', to='organizations.orguser'),
        ),
        migrations.AddField(
            model_name='orguser',
            name='deactivated_at',
            field=models.DateTimeField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name='orguser',
            name='deactivated_by',
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='deactivated_users', to='organizations.orguser'),
        ),
        migrations.AddIndex(
            model_name='orguser',
            index=models.Index(fields=['is_active'], name='org_users_is_acti_8b6c7d_idx'),
        ),
        migrations.AddIndex(
            model_name='orguser',
            index=models.Index(fields=['org', 'is_active'], name='org_users_org_id_is_active_f874e2_idx'),
        ),
    ]