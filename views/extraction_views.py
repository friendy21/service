from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from django.shortcuts import get_object_or_404

import requests

from organization.models.data_source_model import DataSourceConfig
from organization.config.service_endpoints import EXTRACTION_ENDPOINTS
from organization.schema.extraction_schema import (
    extract_start_schema,
    extract_status_schema,
    extract_result_schema,
)


class ExtractStartAPIView(APIView):
    """Starts the data extraction process for a data source."""

    @extract_start_schema()
    def post(self, request, pk):
        data_source = get_object_or_404(DataSourceConfig, pk=pk)
        url = EXTRACTION_ENDPOINTS["start"](data_source.id)

        try:
            payload = data_source.to_dict()
            response = requests.post(url, json=payload)

            if response.status_code == 202:
                data_source.update_extraction_status("in_progress")
                return Response({"message": "Extraction started."}, status=status.HTTP_202_ACCEPTED)

            elif response.status_code == 409:
                error = response.json().get("error", "Extraction already in progress or completed.")
                return Response({"error": error}, status=status.HTTP_409_CONFLICT)

            elif response.status_code == 400:
                error = response.json().get("error", "Bad request to extraction service.")
                return Response({"error": error}, status=status.HTTP_400_BAD_REQUEST)

            data_source.update_extraction_status("failed")
            return Response({"error": "Failed to start extraction."}, status=response.status_code)

        except requests.exceptions.RequestException as e:
            data_source.update_extraction_status("failed")
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class ExtractStatusAPIView(APIView):
    """Get the extraction status for a given data source."""

    @extract_status_schema()
    def get(self, request, pk):
        data_source = get_object_or_404(DataSourceConfig, pk=pk)
        url = EXTRACTION_ENDPOINTS["status"](data_source.id)

        try:
            response = requests.get(url)
            if response.status_code == 200:
                return Response(response.json(), status=status.HTTP_200_OK)

            return Response(
                {"error": "Failed to retrieve status."},
                status=response.status_code,
            )

        except requests.exceptions.RequestException as e:
            return Response(
                {"error": str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )


class ExtractResultAPIView(APIView):
    """Get the result of a completed extraction for a data source."""

    @extract_result_schema()
    def get(self, request, pk):
        data_source = get_object_or_404(DataSourceConfig, pk=pk)
        url = EXTRACTION_ENDPOINTS["result"](data_source.id)

        try:
            response = requests.get(url)

            if response.status_code == 200:
                return Response(response.json(), status=status.HTTP_200_OK)

            elif response.status_code == 202:
                return Response(
                    {"message": "Result not ready."},
                    status=status.HTTP_202_ACCEPTED,
                )

            return Response(
                {"error": "Failed to retrieve result."},
                status=response.status_code,
            )

        except requests.exceptions.RequestException as e:
            return Response(
                {"error": str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )
