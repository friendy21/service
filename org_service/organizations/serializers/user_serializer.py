# org_service/organizations/serializers/user_serializers.py
from rest_framework import serializers
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError
from organizations.models.models import Organization, OrgUser

class UserCreateSerializer(serializers.ModelSerializer):
    """Serializer for creating new users"""
    email = serializers.EmailField(required=True)
    name = serializers.CharField(required=True)
    role = serializers.ChoiceField(choices=OrgUser.ROLE_CHOICES, required=True)
    password = serializers.CharField(write_only=True, required=False, min_length=8)

    class Meta:
        model = OrgUser
        fields = ['email', 'name', 'role', 'password']

    def validate_email(self, value):
        if not value:
            raise serializers.ValidationError("Email is required")
        return value.lower().strip()

    def validate_name(self, value):
        if not value or not value.strip():
            raise serializers.ValidationError("Name is required")
        return value.strip()

    def validate_role(self, value):
        if value not in dict(OrgUser.ROLE_CHOICES):
            raise serializers.ValidationError("Invalid role choice")
        return value

    def validate_password(self, value):
        if value:
            try:
                validate_password(value)
            except ValidationError as e:
                raise serializers.ValidationError(e.messages)
        return value


class UserUpdateSerializer(serializers.ModelSerializer):
    """Serializer for updating user information"""
    name = serializers.CharField(required=False)
    email = serializers.EmailField(required=False)
    
    class Meta:
        model = OrgUser
        fields = ['name', 'email']
        
    def validate_email(self, value):
        if value:
            value = value.lower().strip()
            # Check if email is already taken by another user
            if OrgUser.objects.filter(email=value).exclude(id=self.instance.id).exists():
                raise serializers.ValidationError("User with this email already exists")
        return value

    def validate_name(self, value):
        if value is not None and not value.strip():
            raise serializers.ValidationError("Name cannot be empty")
        return value.strip() if value else value


class UserResponseSerializer(serializers.ModelSerializer):
    """Serializer for user response data"""
    org_id = serializers.CharField(source='org.id')
    org_name = serializers.CharField(source='org.name')
    user_id = serializers.CharField(source='id')
    permissions = serializers.SerializerMethodField()

    class Meta:
        model = OrgUser
        fields = [
            'user_id', 'email', 'name', 'role', 'org_id', 'org_name',
            'is_active', 'is_verified', 'last_login', 'created_at', 
            'updated_at', 'permissions'
        ]

    def get_permissions(self, obj):
        from organizations.permissions import get_user_permissions
        return get_user_permissions(obj)


class UserListSerializer(serializers.ModelSerializer):
    """Serializer for user list view"""
    org_name = serializers.CharField(source='org.name')
    
    class Meta:
        model = OrgUser
        fields = [
            'id', 'email', 'name', 'role', 'org_name',
            'is_active', 'last_login', 'created_at'
        ]


class UserDetailSerializer(serializers.ModelSerializer):
    """Serializer for detailed user view"""
    org_id = serializers.CharField(source='org.id')
    org_name = serializers.CharField(source='org.name')
    created_by_name = serializers.CharField(source='created_by.name', read_only=True)
    deactivated_by_name = serializers.CharField(source='deactivated_by.name', read_only=True)
    
    class Meta:
        model = OrgUser
        fields = [
            'id', 'email', 'name', 'role', 'org_id', 'org_name',
            'is_active', 'is_verified', 'last_login', 'password_changed_at',
            'created_at', 'updated_at', 'created_by_name',
            'deactivated_at', 'deactivated_by_name'
        ]


class ChangePasswordSerializer(serializers.Serializer):
    """Serializer for password change"""
    current_password = serializers.CharField(write_only=True, required=True)
    new_password = serializers.CharField(write_only=True, required=True, min_length=8)
    confirm_password = serializers.CharField(write_only=True, required=True)

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


class RoleUpdateSerializer(serializers.Serializer):
    """Serializer for updating user role"""
    role = serializers.ChoiceField(choices=OrgUser.ROLE_CHOICES, required=True)
    
    def validate_role(self, value):
        if value not in dict(OrgUser.ROLE_CHOICES):
            raise serializers.ValidationError("Invalid role choice")
        return value


class UserDeactivateSerializer(serializers.Serializer):
    """Serializer for user deactivation"""
    reason = serializers.CharField(required=False, max_length=500)


class UserReactivateSerializer(serializers.Serializer):
    """Serializer for user reactivation"""
    reset_password = serializers.BooleanField(default=False)


class InternalUserSerializer(serializers.ModelSerializer):
    """Serializer for internal API responses"""
    user_id = serializers.CharField(source='id')
    org_id = serializers.CharField(source='org.id')

    class Meta:
        model = OrgUser
        fields = ['user_id', 'org_id', 'role']


class OrganizationUsersSerializer(serializers.ModelSerializer):
    """Serializer for organization users list"""
    user_count = serializers.SerializerMethodField()
    users = UserListSerializer(many=True, read_only=True)
    
    class Meta:
        model = Organization
        fields = ['id', 'name', 'user_count', 'users']
    
    def get_user_count(self, obj):
        return obj.users.filter(is_active=True).count()