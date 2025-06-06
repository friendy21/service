from rest_framework import serializers

class LoginSerializer(serializers.Serializer):
    email = serializers.EmailField(required=True)
    password = serializers.CharField(required=True, min_length=1)

    def validate_email(self, value):
        return value.lower().strip()

    def validate(self, attrs):
        if not attrs.get('email'):
            raise serializers.ValidationError("Email is required")
        if not attrs.get('password'):
            raise serializers.ValidationError("Password is required")
        return attrs