from celery import shared_task
from django.core.mail import send_mail
from django.conf import settings
from django.utils import timezone
from django.template.loader import render_to_string
from datetime import timedelta
import logging

logger = logging.getLogger(__name__)

@shared_task(bind=True, max_retries=3)
def send_verification_email(self, user_email, verification_token, user_name=None):
    """
    Send email verification email
    """
    try:
        subject = 'Verify Your Email Address'
        
        # Create verification URL
        verification_url = f"{settings.FRONTEND_URL}/verify-email?token={verification_token}"
        
        # Email context
        context = {
            'user_name': user_name or user_email,
            'verification_url': verification_url,
            'site_name': getattr(settings, 'SITE_NAME', 'Your Service'),
        }
        
        # Render email templates
        html_message = render_to_string('emails/verify_email.html', context)
        text_message = render_to_string('emails/verify_email.txt', context)
        
        # Send email
        send_mail(
            subject=subject,
            message=text_message,
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[user_email],
            html_message=html_message,
            fail_silently=False
        )
        
        logger.info(f"Verification email sent successfully to {user_email}")
        return {'status': 'success', 'email': user_email}
        
    except Exception as exc:
        logger.error(f"Failed to send verification email to {user_email}: {str(exc)}")
        
        # Retry the task
        if self.request.retries < self.max_retries:
            raise self.retry(countdown=60 * (2 ** self.request.retries))
        
        return {'status': 'failed', 'error': str(exc)}


@shared_task(bind=True, max_retries=3)
def send_password_reset_email(self, user_email, reset_token, user_name=None):
    """
    Send password reset email
    """
    try:
        subject = 'Reset Your Password'
        
        # Create reset URL
        reset_url = f"{settings.FRONTEND_URL}/reset-password?token={reset_token}"
        
        # Email context
        context = {
            'user_name': user_name or user_email,
            'reset_url': reset_url,
            'site_name': getattr(settings, 'SITE_NAME', 'Your Service'),
            'expiry_hours': 1,  # Password reset tokens expire in 1 hour
        }
        
        # Render email templates
        html_message = render_to_string('emails/password_reset.html', context)
        text_message = render_to_string('emails/password_reset.txt', context)
        
        # Send email
        send_mail(
            subject=subject,
            message=text_message,
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[user_email],
            html_message=html_message,
            fail_silently=False
        )
        
        logger.info(f"Password reset email sent successfully to {user_email}")
        return {'status': 'success', 'email': user_email}
        
    except Exception as exc:
        logger.error(f"Failed to send password reset email to {user_email}: {str(exc)}")
        
        # Retry the task
        if self.request.retries < self.max_retries:
            raise self.retry(countdown=60 * (2 ** self.request.retries))
        
        return {'status': 'failed', 'error': str(exc)}


@shared_task
def send_security_alert_email(user_email, alert_type, details, user_name=None):
    """
    Send security alert emails
    """
    try:
        alert_subjects = {
            'new_device_login': 'New Device Login Detected',
            'password_changed': 'Password Changed Successfully',
            'suspicious_activity': 'Suspicious Activity Detected',
            'account_locked': 'Account Temporarily Locked',
            'multiple_failed_logins': 'Multiple Failed Login Attempts',
        }
        
        subject = alert_subjects.get(alert_type, 'Security Alert')
        
        # Email context
        context = {
            'user_name': user_name or user_email,
            'alert_type': alert_type,
            'details': details,
            'site_name': getattr(settings, 'SITE_NAME', 'Your Service'),
            'timestamp': timezone.now(),
        }
        
        # Render email templates
        html_message = render_to_string('emails/security_alert.html', context)
        text_message = render_to_string('emails/security_alert.txt', context)
        
        # Send email
        send_mail(
            subject=subject,
            message=text_message,
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[user_email],
            html_message=html_message,
            fail_silently=False
        )
        
        logger.info(f"Security alert email sent successfully to {user_email}")
        return {'status': 'success', 'email': user_email}
        
    except Exception as exc:
        logger.error(f"Failed to send security alert email to {user_email}: {str(exc)}")
        return {'status': 'failed', 'error': str(exc)}


@shared_task
def cleanup_expired_sessions():
    """
    Clean up expired user sessions
    """
    try:
        from authentication.models.models import UserSession
        
        # Mark expired sessions
        expired_count = UserSession.objects.filter(
            expires_at__lt=timezone.now(),
            status='active'
        ).update(status='expired')
        
        # Delete very old sessions (older than 30 days)
        old_threshold = timezone.now() - timedelta(days=30)
        deleted_count = UserSession.objects.filter(
            created_at__lt=old_threshold
        ).delete()[0]
        
        logger.info(f"Session cleanup: {expired_count} expired, {deleted_count} deleted")
        return {
            'expired_sessions': expired_count,
            'deleted_sessions': deleted_count
        }
        
    except Exception as exc:
        logger.error(f"Failed to cleanup sessions: {str(exc)}")
        return {'status': 'failed', 'error': str(exc)}


@shared_task
def cleanup_expired_tokens():
    """
    Clean up expired verification and reset tokens
    """
    try:
        from authentication.models.models import EmailVerification, PasswordResetToken
        
        now = timezone.now()
        
        # Delete expired email verification tokens
        expired_verifications = EmailVerification.objects.filter(
            expires_at__lt=now
        ).delete()[0]
        
        # Delete expired password reset tokens
        expired_resets = PasswordResetToken.objects.filter(
            expires_at__lt=now
        ).delete()[0]
        
        logger.info(f"Token cleanup: {expired_verifications} verification tokens, {expired_resets} reset tokens deleted")
        return {
            'deleted_verification_tokens': expired_verifications,
            'deleted_reset_tokens': expired_resets
        }
        
    except Exception as exc:
        logger.error(f"Failed to cleanup tokens: {str(exc)}")
        return {'status': 'failed', 'error': str(exc)}


@shared_task
def cleanup_old_audit_logs():
    """
    Clean up old audit logs (keep last 90 days)
    """
    try:
        from authentication.models.models import AuditLog
        
        # Keep logs for 90 days
        cutoff_date = timezone.now() - timedelta(days=90)
        deleted_count = AuditLog.objects.filter(
            timestamp__lt=cutoff_date
        ).delete()[0]
        
        logger.info(f"Audit log cleanup: {deleted_count} old logs deleted")
        return {'deleted_logs': deleted_count}
        
    except Exception as exc:
        logger.error(f"Failed to cleanup audit logs: {str(exc)}")
        return {'status': 'failed', 'error': str(exc)}


@shared_task
def generate_security_report():
    """
    Generate daily security report
    """
    try:
        from authentication.models.models import AuditLog, AuthUser, UserSession
        from django.db.models import Count
        
        # Get stats for last 24 hours
        last_24h = timezone.now() - timedelta(hours=24)
        
        stats = {
            'successful_logins': AuditLog.objects.filter(
                action='login_success',
                timestamp__gte=last_24h
            ).count(),
            'failed_logins': AuditLog.objects.filter(
                action='login_failed',
                timestamp__gte=last_24h
            ).count(),
            'password_resets': AuditLog.objects.filter(
                action='password_reset_requested',
                timestamp__gte=last_24h
            ).count(),
            'locked_accounts': AuthUser.objects.filter(
                locked_until__isnull=False,
                locked_until__gt=timezone.now()
            ).count(),
            'active_sessions': UserSession.objects.filter(
                status='active'
            ).count(),
        }
        
        # Calculate login success rate
        total_login_attempts = stats['successful_logins'] + stats['failed_logins']
        if total_login_attempts > 0:
            stats['success_rate'] = (stats['successful_logins'] / total_login_attempts) * 100
        else:
            stats['success_rate'] = 100
        
        # Get top failed login IPs
        failed_login_ips = AuditLog.objects.filter(
            action='login_failed',
            timestamp__gte=last_24h
        ).values('ip_address').annotate(
            count=Count('ip_address')
        ).order_by('-count')[:10]
        
        stats['top_failed_ips'] = list(failed_login_ips)
        
        logger.info(f"Security report generated: {stats}")
        
        # Send report to administrators if configured
        admin_emails = getattr(settings, 'ADMIN_EMAIL_LIST', [])
        if admin_emails and stats['failed_logins'] > 50:  # Alert threshold
            send_admin_security_alert.delay(stats)
        
        return stats
        
    except Exception as exc:
        logger.error(f"Failed to generate security report: {str(exc)}")
        return {'status': 'failed', 'error': str(exc)}


@shared_task
def send_admin_security_alert(stats):
    """
    Send security alert to administrators
    """
    try:
        admin_emails = getattr(settings, 'ADMIN_EMAIL_LIST', [])
        if not admin_emails:
            return {'status': 'skipped', 'reason': 'no_admin_emails'}
        
        subject = 'Security Alert: High Failed Login Activity'
        
        context = {
            'stats': stats,
            'site_name': getattr(settings, 'SITE_NAME', 'Your Service'),
            'timestamp': timezone.now(),
        }
        
        # Render email templates
        html_message = render_to_string('emails/admin_security_alert.html', context)
        text_message = render_to_string('emails/admin_security_alert.txt', context)
        
        # Send email to all administrators
        send_mail(
            subject=subject,
            message=text_message,
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=admin_emails,
            html_message=html_message,
            fail_silently=False
        )
        
        logger.info(f"Admin security alert sent to {len(admin_emails)} administrators")
        return {'status': 'success', 'recipients': len(admin_emails)}
        
    except Exception as exc:
        logger.error(f"Failed to send admin security alert: {str(exc)}")
        return {'status': 'failed', 'error': str(exc)}


@shared_task
def detect_and_alert_suspicious_activity():
    """
    Detect suspicious activity patterns and send alerts
    """
    try:
        from authentication.models.models import AuditLog, AuthUser
        from django.db.models import Count, Q
        from collections import defaultdict
        
        # Look for suspicious patterns in last hour
        last_hour = timezone.now() - timedelta(hours=1)
        
        suspicious_activities = []
        
        # 1. Multiple failed logins from same IP
        failed_by_ip = AuditLog.objects.filter(
            action='login_failed',
            timestamp__gte=last_hour
        ).values('ip_address').annotate(
            count=Count('ip_address'),
            users=Count('user', distinct=True)
        ).filter(count__gte=10)  # 10+ failed attempts
        
        for item in failed_by_ip:
            suspicious_activities.append({
                'type': 'multiple_failed_logins_ip',
                'ip_address': item['ip_address'],
                'failed_attempts': item['count'],
                'affected_users': item['users']
            })
        
        # 2. Single user with multiple failed attempts
        failed_by_user = AuditLog.objects.filter(
            action='login_failed',
            timestamp__gte=last_hour,
            user__isnull=False
        ).values('user__email').annotate(
            count=Count('user'),
            ips=Count('ip_address', distinct=True)
        ).filter(count__gte=5)  # 5+ failed attempts
        
        for item in failed_by_user:
            suspicious_activities.append({
                'type': 'multiple_failed_logins_user',
                'user_email': item['user__email'],
                'failed_attempts': item['count'],
                'from_ips': item['ips']
            })
        
        # 3. Rapid logins from different locations
        rapid_logins = AuditLog.objects.filter(
            action='login_success',
            timestamp__gte=last_hour
        ).values('user__email').annotate(
            count=Count('user'),
            ips=Count('ip_address', distinct=True)
        ).filter(ips__gte=3)  # 3+ different IPs
        
        for item in rapid_logins:
            suspicious_activities.append({
                'type': 'rapid_location_changes',
                'user_email': item['user__email'],
                'login_count': item['count'],
                'different_ips': item['ips']
            })
        
        # 4. Account enumeration attempts
        failed_nonexistent = AuditLog.objects.filter(
            action='login_failed',
            timestamp__gte=last_hour,
            user__isnull=True,
            details__reason='user_not_found'
        ).values('ip_address').annotate(
            count=Count('ip_address')
        ).filter(count__gte=20)  # 20+ attempts on non-existent users
        
        for item in failed_nonexistent:
            suspicious_activities.append({
                'type': 'account_enumeration',
                'ip_address': item['ip_address'],
                'enumeration_attempts': item['count']
            })
        
        # Send alerts for suspicious activities
        if suspicious_activities:
            logger.warning(f"Detected {len(suspicious_activities)} suspicious activities")
            
            # Send immediate alert to administrators
            admin_emails = getattr(settings, 'ADMIN_EMAIL_LIST', [])
            if admin_emails:
                send_suspicious_activity_alert.delay(suspicious_activities)
            
            # Auto-lock accounts with too many failed attempts
            for activity in suspicious_activities:
                if activity['type'] == 'multiple_failed_logins_user':
                    try:
                        user = AuthUser.objects.get(email=activity['user_email'])
                        if activity['failed_attempts'] >= 10:
                            user.locked_until = timezone.now() + timedelta(hours=1)
                            user.save()
                            logger.info(f"Auto-locked user {user.email} due to suspicious activity")
                    except AuthUser.DoesNotExist:
                        continue
        
        return {
            'suspicious_activities_found': len(suspicious_activities),
            'activities': suspicious_activities
        }
        
    except Exception as exc:
        logger.error(f"Failed to detect suspicious activity: {str(exc)}")
        return {'status': 'failed', 'error': str(exc)}


@shared_task
def send_suspicious_activity_alert(activities):
    """
    Send suspicious activity alert to administrators
    """
    try:
        admin_emails = getattr(settings, 'ADMIN_EMAIL_LIST', [])
        if not admin_emails:
            return {'status': 'skipped', 'reason': 'no_admin_emails'}
        
        subject = 'URGENT: Suspicious Activity Detected'
        
        context = {
            'activities': activities,
            'site_name': getattr(settings, 'SITE_NAME', 'Your Service'),
            'timestamp': timezone.now(),
            'activity_count': len(activities)
        }
        
        # Render email templates
        html_message = render_to_string('emails/suspicious_activity_alert.html', context)
        text_message = render_to_string('emails/suspicious_activity_alert.txt', context)
        
        # Send email to all administrators
        send_mail(
            subject=subject,
            message=text_message,
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=admin_emails,
            html_message=html_message,
            fail_silently=False
        )
        
        logger.info(f"Suspicious activity alert sent to {len(admin_emails)} administrators")
        return {'status': 'success', 'recipients': len(admin_emails)}
        
    except Exception as exc:
        logger.error(f"Failed to send suspicious activity alert: {str(exc)}")
        return {'status': 'failed', 'error': str(exc)}


@shared_task
def backup_security_logs():
    """
    Backup security-related logs to external storage
    """
    try:
        from authentication.models.models import AuditLog
        import json
        from django.core.serializers import serialize
        
        # Get logs from last 24 hours
        last_24h = timezone.now() - timedelta(hours=24)
        
        logs = AuditLog.objects.filter(
            timestamp__gte=last_24h
        ).order_by('timestamp')
        
        if not logs.exists():
            return {'status': 'skipped', 'reason': 'no_logs_to_backup'}
        
        # Serialize logs
        logs_data = []
        for log in logs:
            logs_data.append({
                'id': str(log.id),
                'user_email': log.user.email if log.user else None,
                'action': log.action,
                'ip_address': log.ip_address,
                'user_agent': log.user_agent,
                'details': log.details,
                'timestamp': log.timestamp.isoformat()
            })
        
        # Create backup filename
        backup_filename = f"security_logs_{timezone.now().strftime('%Y%m%d_%H%M%S')}.json"
        
        # Save to file (in production, this would be sent to S3, etc.)
        backup_dir = settings.BASE_DIR / 'backups'
        backup_dir.mkdir(exist_ok=True)
        
        backup_path = backup_dir / backup_filename
        with open(backup_path, 'w') as f:
            json.dump(logs_data, f, indent=2)
        
        logger.info(f"Security logs backed up: {len(logs_data)} logs to {backup_filename}")
        
        # TODO: In production, upload to S3 or other cloud storage
        # upload_to_s3(backup_path, backup_filename)
        
        return {
            'status': 'success',
            'logs_backed_up': len(logs_data),
            'backup_file': backup_filename
        }
        
    except Exception as exc:
        logger.error(f"Failed to backup security logs: {str(exc)}")
        return {'status': 'failed', 'error': str(exc)}


@shared_task
def update_user_session_metadata(session_id, ip_address, user_agent):
    """
    Update session metadata with additional information
    """
    try:
        from authentication.models.models import UserSession
        import user_agents
        
        session = UserSession.objects.get(id=session_id)
        
        # Parse user agent
        ua = user_agents.parse(user_agent)
        
        # Update session with parsed information
        session.user_agent = user_agent
        session.ip_address = ip_address
        
        # Extract device information if not already set
        if not session.device_name and ua.browser.family:
            session.device_name = f"{ua.browser.family} on {ua.os.family}"
        
        if not session.device_type or session.device_type == 'unknown':
            if ua.is_mobile:
                session.device_type = 'mobile'
            elif ua.is_tablet:
                session.device_type = 'tablet'
            elif ua.is_pc:
                session.device_type = 'web'
            else:
                session.device_type = 'unknown'
        
        session.save()
        
        logger.info(f"Updated session metadata for session {session_id}")
        return {'status': 'success', 'session_id': str(session_id)}
        
    except UserSession.DoesNotExist:
        logger.warning(f"Session {session_id} not found for metadata update")
        return {'status': 'failed', 'error': 'session_not_found'}
    except Exception as exc:
        logger.error(f"Failed to update session metadata: {str(exc)}")
        return {'status': 'failed', 'error': str(exc)}


@shared_task
def send_login_notification(user_email, session_info, is_new_device=False):
    """
    Send login notification to user
    """
    try:
        if not getattr(settings, 'SEND_LOGIN_NOTIFICATIONS', True):
            return {'status': 'skipped', 'reason': 'notifications_disabled'}
        
        # Don't send notifications for every login, only for new devices or suspicious activity
        if not is_new_device:
            return {'status': 'skipped', 'reason': 'not_new_device'}
        
        subject = 'New Device Login Detected'
        
        context = {
            'user_email': user_email,
            'session_info': session_info,
            'site_name': getattr(settings, 'SITE_NAME', 'Your Service'),
            'timestamp': timezone.now(),
            'is_new_device': is_new_device
        }
        
        # Render email templates
        html_message = render_to_string('emails/login_notification.html', context)
        text_message = render_to_string('emails/login_notification.txt', context)
        
        # Send email
        send_mail(
            subject=subject,
            message=text_message,
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[user_email],
            html_message=html_message,
            fail_silently=False
        )
        
        logger.info(f"Login notification sent to {user_email}")
        return {'status': 'success', 'email': user_email}
        
    except Exception as exc:
        logger.error(f"Failed to send login notification to {user_email}: {str(exc)}")
        return {'status': 'failed', 'error': str(exc)}