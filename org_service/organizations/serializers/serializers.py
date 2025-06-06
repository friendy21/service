from rest_framework import serializers
from organizations.models.models import Organization, OrgUser

class UserCreateSerializer(serializers.ModelSerializer):
    # Ensure all fields are required for user creation
    email = serializers.EmailField(required=True)
    name = serializers.CharField(required=True)
    role = serializers.ChoiceField(choices=OrgUser.ROLE_CHOICES, required=True)

    class Meta:
        model = OrgUser
        fields = ['email', 'name', 'role']

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

class UserResponseSerializer(serializers.ModelSerializer):
    org_id = serializers.CharField(source='org.id')
    user_id = serializers.CharField(source='id')

    class Meta:
        model = OrgUser
        fields = ['user_id', 'email', 'org_id', 'role']

class InternalUserSerializer(serializers.ModelSerializer):
    user_id = serializers.CharField(source='id')
    org_id = serializers.CharField(source='org.id')

    class Meta:
        model = OrgUser
        fields = ['user_id', 'org_id', 'role']