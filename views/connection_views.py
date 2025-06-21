from rest_framework import status
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.generics import get_object_or_404
from organization.models.data_source_model import DataSourceConfig
from organization.services.connection_service import ConnectionService, ConnectionValidationError

from organization.serializers.connection_serializer import ConnectionValidationResponseSerializer

from rest_framework import status
from rest_framework.views import APIView
from rest_framework.response import Response
from organization.models.data_source_model import DataSourceConfig
from organization.services.connection_service import ConnectionService

class DataSourceConnectAPIView(APIView):
    def post(self, request, pk):
        data_source = get_object_or_404(DataSourceConfig, pk=pk)
        response_data, response_status = ConnectionService.check_connection_and_prepare_response(data_source)
        return Response(response_data, status=response_status)
