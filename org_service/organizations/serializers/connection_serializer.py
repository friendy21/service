from rest_framework import serializers

class ConnectionValidationResponseSerializer(serializers.Serializer):
    status = serializers.CharField()
    message = serializers.CharField()
    error_code = serializers.CharField(required=False)
    connection_id = serializers.CharField(required=False) 