# organization/serializers/extraction_serializer.py

from rest_framework import serializers



class ExtractStartResponseSerializer(serializers.Serializer):
    """
    Serializer for a successful start extraction response.
    """
    message = serializers.CharField(help_text="Confirmation that extraction was started.")


class ExtractStatusResponseSerializer(serializers.Serializer):
    """
    Serializer for checking the extraction status.
    """
    status = serializers.CharField(help_text="Current status of the extraction.")
    last_updated = serializers.DateTimeField(help_text="Last updated timestamp of the status.")


class ExtractResultResponseSerializer(serializers.Serializer):
    """
    Serializer for returning extraction results.
    """
    result = serializers.JSONField(help_text="Final extracted result data.")


class ExtractErrorSerializer(serializers.Serializer):
    """
    Generic error response for extraction endpoints.
    """
    error = serializers.CharField(help_text="Error message if the operation fails.")
