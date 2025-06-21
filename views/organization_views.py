from django.contrib.auth import logout
from django.shortcuts import get_object_or_404, redirect
from django.views import View
from drf_yasg.utils import swagger_auto_schema
from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView

from ..models.organization_model import  Organization
from ..serializers.organization_serializers import (
    CreateOrganizationSerializer,
    OrganizationSerializer,
    UpdateOrganizationSerializer
)

class CustomLogoutView(View):
    def get(self, request, *args, **kwargs):
        """Handle GET logout requests."""
        logout(request)
        return redirect("/swagger/")  # ✅ Redirect after logout

# ================================
# 🚀 ORGANIZATION CRUD API
# ================================
class OrganizationCreateAPIView(APIView):
    """Create a new organization."""

    @swagger_auto_schema(
        request_body=CreateOrganizationSerializer,
        responses={201: OrganizationSerializer, 400: "Bad Request"},
    )
    def post(self, request, *args, **kwargs):
        data = request.data.copy()  # Copy request data to modify
        serializer = CreateOrganizationSerializer(data=data)
        if serializer.is_valid():
            organization = serializer.save()
            return Response(
                OrganizationSerializer(organization).data,
                status=status.HTTP_201_CREATED,
            )
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class OrganizationRetrieveAPIView(APIView):
    """Retrieve an organization by ID."""

    @swagger_auto_schema(responses={200: OrganizationSerializer, 404: "Not Found"})
    def get(self, request, pk, *args, **kwargs):
        organization = get_object_or_404(Organization, pk=pk)
        serializer = OrganizationSerializer(organization)
        return Response(serializer.data, status=status.HTTP_200_OK)


class OrganizationListAPIView(APIView):
    """List all organizations."""

    @swagger_auto_schema(responses={200: OrganizationSerializer(many=True)})
    def get(self, request, *args, **kwargs):
        organizations = Organization.objects.all()
        serializer = OrganizationSerializer(organizations, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)


class OrganizationUpdateAPIView(APIView):
    """Update an organization."""

    @swagger_auto_schema(
        request_body=UpdateOrganizationSerializer,
        responses={200: OrganizationSerializer, 400: "Bad Request", 404: "Not Found"},
    )
    def put(self, request, pk, *args, **kwargs):
        organization = get_object_or_404(Organization, pk=pk)
        serializer = UpdateOrganizationSerializer(
            organization, data=request.data, partial=True
        )
        if serializer.is_valid():
            serializer.save()
            return Response(
                OrganizationSerializer(organization).data, status=status.HTTP_200_OK
            )
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class OrganizationDeleteAPIView(APIView):
    """Delete an organization by ID."""

    @swagger_auto_schema(responses={204: "No Content", 404: "Not Found"})
    def delete(self, request, pk, *args, **kwargs):
        organization = get_object_or_404(Organization, pk=pk)
        organization.delete()
        return Response(
            {"message": "Organization deleted successfully"},
            status=status.HTTP_204_NO_CONTENT,
        )