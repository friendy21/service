# organization/schema/extraction_schema.py

from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi
from organization.serializers.extraction_serializer import (
    ExtractStartResponseSerializer,
    ExtractStatusResponseSerializer,
    ExtractResultResponseSerializer,
    ExtractErrorSerializer
)

def extract_start_schema():
    return swagger_auto_schema(
        operation_description="Initiate extraction using the configured data source.",
        responses={
            202: ExtractStartResponseSerializer,
            400: ExtractErrorSerializer,
            404: "Not Found",
            500: ExtractErrorSerializer,
        }
    )

def extract_status_schema():
    return swagger_auto_schema(
        operation_description="Check the current status of the extraction process.",
        responses={
            200: ExtractStatusResponseSerializer,
            404: "Not Found",
            500: ExtractErrorSerializer,
        }
    )

def extract_result_schema():
    return swagger_auto_schema(
        operation_description="Retrieve the result of the completed data extraction.",
        responses={
            200: ExtractResultResponseSerializer,
            202: openapi.Response(description="Result not ready."),
            404: "Not Found",
            500: ExtractErrorSerializer,
        }
    )
