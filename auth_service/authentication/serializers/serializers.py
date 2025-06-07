from rest_framework import serializers
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError

class LoginSerializer(serializers.Serializer):
    email = serializers.EmailField(required=True)
    password = serializers.CharField(required=True, min_length=1)
    remember_me = serializers.BooleanField(default=False, required=False)

    def validate_email(self, value):
        return value.lower().strip()

    def validate(self, attrs):
        if not attrs.get('email'):
            raise serializers.ValidationError("Email is required")
        if not attrs.get('password'):
            raise serializers.ValidationError("Password is required")
        return attrs


class LogoutSerializer(serializers.Serializer):
    session_token = serializers.CharField(required=False, allow_blank=True)


class RefreshTokenSerializer(serializers.Serializer):
    refresh_token = serializers.CharField(required=True)

    def validate_refresh_token(self, value):
        if not value or not value.strip():
            raise serializers.ValidationError("Refresh token is required")
        return value.strip()


class PasswordResetRequestSerializer(serializers.Serializer):
    email = serializers.EmailField(required=True)

    def validate_email(self, value):
        return value.lower().strip()


class PasswordResetConfirmSerializer(serializers.Serializer):
    token = serializers.CharField(required=True)
    new_password = serializers.CharField(required=True, min_length=8, write_only=True)
    confirm_password = serializers.CharField(required=True, min_length=8, write_only=True)

    def validate_new_password(self, value):
        try:
            validate_password(value)
        except ValidationError as e:
            raise serializers.ValidationError(e.messages)
        return value

    def validate(self, attrs):
        if attrs['new_password'] != attrs['confirm_password']:
            raise serializers.ValidationError("Passwords do not match")
        return attrs


class ChangePasswordSerializer(serializers.Serializer):
    current_password = serializers.CharField(required=True, write_only=True)
    new_password = serializers.CharField(required=True, min_length=8, write_only=True)
    confirm_password = serializers.CharField(required=True, min_length=8, write_only=True)
    logout_all_devices = serializers.BooleanField(default=False, required=False)

    def validate_new_password(self, value):
        try:
            validate_password(value)
        except ValidationError as e:
            raise serializers.ValidationError(e.messages)
        return value

    def validate(self, attrs):
        if attrs['new_password'] != attrs['confirm_password']:
            raise serializers.ValidationError("New passwords do not match")
        
        if attrs['current_password'] == attrs['new_password']:
            raise serializers.ValidationError("New password must be different from current password")
        
        return attrs


class EmailVerificationSerializer(serializers.Serializer):
    token = serializers.CharField(required=True)

    def validate_token(self, value):
        if not value or not value.strip():
            raise serializers.ValidationError("Verification token is required")
        return value.strip()


class UserSessionSerializer(serializers.Serializer):
    id = serializers.UUIDField(read_only=True)
    device_type = serializers.CharField(read_only=True)
    device_name = serializers.CharField(read_only=True)
    ip_address = serializers.IPAddressField(read_only=True)
    user_agent = serializers.CharField(read_only=True)
    created_at = serializers.DateTimeField(read_only=True)
    last_accessed = serializers.DateTimeField(read_only=True)
    expires_at = serializers.DateTimeField(read_only=True)
    is_current = serializers.SerializerMethodField()

    def get_is_current(self, obj):
        request = self.context.get('request')
        if request:
            # Check if this is the current session based on JWT
            auth_header = request.headers.get('Authorization', '')
            if auth_header.startswith('Bearer '):
                try:
                    import jwt
                    from django.conf import settings
                    jwt_token = auth_header[7:]
                    payload = jwt.decode(jwt_token, settings.JWT_SECRET, algorithms=['HS256'])
                    return payload.get('session_id') == str(obj.id)
                except:
                    pass
        return False


class SecuritySummarySerializer(serializers.Serializer):
    active_sessions = serializers.IntegerField(read_only=True)
    last_login = serializers.DateTimeField(read_only=True)
    password_changed_at = serializers.DateTimeField(read_only=True)
    failed_attempts = serializers.IntegerField(read_only=True)
    is_locked = serializers.BooleanField(read_only=True)
    is_verified = serializers.BooleanField(read_only=True)
    recent_logins = serializers.IntegerField(read_only=True)
    recent_devices = serializers.ListField(read_only=True)


class AuditLogSerializer(serializers.Serializer):
    action = serializers.CharField(read_only=True)
    ip_address = serializers.IPAddressField(read_only=True)
    user_agent = serializers.CharField(read_only=True)
    details = serializers.JSONField(read_only=True)
    timestamp = serializers.DateTimeField(read_only=True)


class UserRegistrationSerializer(serializers.Serializer):
    """For user registration if needed"""
    email = serializers.EmailField(required=True)
    password = serializers.CharField(required=True, min_length=8, write_only=True)
    confirm_password = serializers.CharField(required=True, min_length=8, write_only=True)
    name = serializers.CharField(required=True, max_length=255)
    terms_accepted = serializers.BooleanField(required=True)

    def validate_email(self, value):
        email = value.lower().strip()
        from authentication.models.models import AuthUser
        if AuthUser.objects.filter(email=email).exists():
            raise serializers.ValidationError("User with this email already exists")
        return email

    def validate_password(self, value):
        try:
            validate_password(value)
        except ValidationError as e:
            raise serializers.ValidationError(e.messages)
        return value

    def validate_terms_accepted(self, value):
        if not value:
            raise serializers.ValidationError("Terms and conditions must be accepted")
        return value

    def validate(self, attrs):
        if attrs['password'] != attrs['confirm_password']:
            raise serializers.ValidationError("Passwords do not match")
        return attrs


class TokenValidationSerializer(serializers.Serializer):
    """For validating JWT tokens"""
    token = serializers.CharField(required=True)


class UserProfileSerializer(serializers.Serializer):
    """Basic user profile information"""
    email = serializers.EmailField(read_only=True)
    is_verified = serializers.BooleanField(read_only=True)
    is_active = serializers.BooleanField(read_only=True)
    last_login = serializers.DateTimeField(read_only=True)
    created_at = serializers.DateTimeField(read_only=True)


class ResendVerificationSerializer(serializers.Serializer):
    """For resending email verification"""
    email = serializers.EmailField(required=True)

    def validate_email(self, value):
        return value.lower().strip()