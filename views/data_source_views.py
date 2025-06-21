import uuid
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from drf_yasg.utils import swagger_auto_schema
from django.shortcuts import get_object_or_404

from organization.models.data_source_model import DataSourceConfig
from organization.serializers.data_source_serializer import (
    DataSourceConfigSerializer,
    CreateDataSourceConfigSerializer,
    UpdateDataSourceConfigSerializer
)
from organization.config.service_endpoints import SERVICE_ENDPOINTS

class DataSourceConfigCreateAPIView(APIView):
    """Create a new data source configuration."""

    @swagger_auto_schema(
        request_body=CreateDataSourceConfigSerializer,
        responses={201: DataSourceConfigSerializer, 400: "Bad Request"},
    )
    def post(self, request, *args, **kwargs):
        data = request.data.copy()
        serializer = CreateDataSourceConfigSerializer(data=data)
        if serializer.is_valid():
            instance = serializer.save()
            output_serializer = DataSourceConfigSerializer(instance)
            return Response(output_serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class DataSourceConfigRetrieveAPIView(APIView):
    """Retrieve a data source configuration by ID."""

    @swagger_auto_schema(responses={200: DataSourceConfigSerializer, 404: "Not Found"})
    def get(self, request, pk, *args, **kwargs):
        data_source = get_object_or_404(DataSourceConfig, pk=pk)
        serializer = DataSourceConfigSerializer(data_source)
        return Response(serializer.data, status=status.HTTP_200_OK)

class DataSourceConfigListAPIView(APIView):
    """List all data source configurations."""

    @swagger_auto_schema(responses={200: DataSourceConfigSerializer(many=True)})
    def get(self, request, *args, **kwargs):
        data_sources = DataSourceConfig.objects.all()
        serializer = DataSourceConfigSerializer(data_sources, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)

class DataSourceConfigUpdateAPIView(APIView):
    """Update a data source configuration."""

    @swagger_auto_schema(
        request_body=UpdateDataSourceConfigSerializer,
        responses={200: DataSourceConfigSerializer, 400: "Bad Request", 404: "Not Found"},
    )
    def put(self, request, pk, *args, **kwargs):
        data_source = get_object_or_404(DataSourceConfig, pk=pk)
        serializer = UpdateDataSourceConfigSerializer(
            data_source, data=request.data, partial=True
        )
        if serializer.is_valid():
            serializer.save()
            return Response(
                DataSourceConfigSerializer(data_source).data,
                status=status.HTTP_200_OK
            )
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class DataSourceConfigDeleteAPIView(APIView):
    """Delete a data source configuration."""

    @swagger_auto_schema(responses={204: "No Content", 404: "Not Found"})
    def delete(self, request, pk, *args, **kwargs):
        data_source = get_object_or_404(DataSourceConfig, pk=pk)
        data_source.delete()
        return Response(
            {"message": "Data source configuration deleted successfully"},
            status=status.HTTP_204_NO_CONTENT,
        ) 