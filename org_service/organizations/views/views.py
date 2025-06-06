from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from django.db import transaction, IntegrityError
from django.shortcuts import get_object_or_404
from django.core.exceptions import ValidationError
from organizations.models.models import Organization, OrgUser
from organizations.serializers.serializers import UserCreateSerializer, UserResponseSerializer, InternalUserSerializer
from organizations.permissions import ServiceTokenPermission
import logging

logger = logging.getLogger(__name__)

class UserCreateView(APIView):
    def post(self, request, org_id):
        """
        Create a new user in the specified organization
        """
        try:
            # Validate organization exists
            org = Organization.objects.filter(id=org_id).first()
            if not org:
                return Response({
                    "message": "Validation failed",
                    "errors": {"org_id": ["Organization does not exist."]}
                }, status=status.HTTP_404_NOT_FOUND)
            
            # Validate request data
            serializer = UserCreateSerializer(data=request.data)
            if not serializer.is_valid():
                return Response({
                    "message": "Validation failed",
                    "errors": serializer.errors
                }, status=status.HTTP_400_BAD_REQUEST)

            # Create user with transaction and select_for_update for concurrency
            with transaction.atomic():
                # Check for email uniqueness with row-level locking
                if OrgUser.objects.select_for_update().filter(
                    email=serializer.validated_data['email']
                ).exists():
                    return Response({
                        "message": "User with this email already exists",
                        "detail": "Email must be unique"
                    }, status=status.HTTP_409_CONFLICT)

                # Create the user
                user = OrgUser.objects.create(
                    org=org,
                    **serializer.validated_data
                )

            # Return success response
            response_serializer = UserResponseSerializer(user)
            response_data = {
                "message": "User account created successfully",
                **response_serializer.data
            }
            
            logger.info(f"User created successfully: {user.email} in org {org.name}")
            return Response(response_data, status=status.HTTP_201_CREATED)

        except IntegrityError as e:
            logger.error(f"Integrity error creating user: {str(e)}")
            return Response({
                "message": "User with this email already exists",
                "detail": "Email must be unique"
            }, status=status.HTTP_409_CONFLICT)
        
        except ValidationError as e:
            logger.error(f"Validation error creating user: {str(e)}")
            return Response({
                "message": "Validation failed",
                "detail": str(e)
            }, status=status.HTTP_400_BAD_REQUEST)
        
        except Exception as e:
            logger.error(f"Unexpected error creating user: {str(e)}")
            return Response({
                "message": "Internal server error",
                "detail": str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class InternalUserView(APIView):
    permission_classes = [ServiceTokenPermission]

    def get(self, request, email):
        """
        Internal API to get user information by email for auth service
        """
        try:
            user = get_object_or_404(OrgUser, email=email.lower())
            serializer = InternalUserSerializer(user)
            return Response(serializer.data, status=status.HTTP_200_OK)
        
        except Exception as e:
            logger.error(f"Error retrieving user {email}: {str(e)}")
            return Response({
                "message": "User not found",
                "detail": str(e)
            }, status=status.HTTP_404_NOT_FOUND)
