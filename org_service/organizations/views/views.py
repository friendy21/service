from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from django.db import transaction, IntegrityError
from django.shortcuts import get_object_or_404
from django.core.exceptions import ValidationError
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi
from organizations.models.models import Organization, OrgUser
from organizations.serializers.serializers import UserCreateSerializer, UserResponseSerializer, InternalUserSerializer
from organizations.permissions import ServiceTokenPermission
import logging

logger = logging.getLogger(__name__)

class UserCreateView(APIView):
    """
    User Management Endpoint
    
    Creates new users within specified organizations with role-based access control.
    """
    
    @swagger_auto_schema(
        operation_summary="Create User",
        operation_description="""
        Create a new user in the specified organization.
        
        ## User Roles
        - **admin**: Full administrative privileges
        - **member**: Standard user access (default)
        - **viewer**: Read-only access
        
        ## Email Uniqueness
        Email addresses must be unique across the entire system, not just within organizations.
        """,
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            required=['email', 'name', 'role'],
            properties={
                'email': openapi.Schema(
                    type=openapi.TYPE_STRING,
                    format=openapi.FORMAT_EMAIL,
                    description='Unique email address for the user',
                    example='john.doe@example.com'
                ),
                'name': openapi.Schema(
                    type=openapi.TYPE_STRING,
                    description='Full name of the user',
                    example='John Doe'
                ),
                'role': openapi.Schema(
                    type=openapi.TYPE_STRING,
                    enum=['admin', 'member', 'viewer'],
                    description='User role within the organization',
                    example='member'
                ),
            },
        ),
        responses={
            201: openapi.Response(
                description="User created successfully",
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'message': openapi.Schema(type=openapi.TYPE_STRING),
                        'user_id': openapi.Schema(type=openapi.TYPE_STRING, format=openapi.FORMAT_UUID),
                        'email': openapi.Schema(type=openapi.TYPE_STRING),
                        'org_id': openapi.Schema(type=openapi.TYPE_STRING, format=openapi.FORMAT_UUID),
                        'role': openapi.Schema(type=openapi.TYPE_STRING),
                    }
                )
            ),
            400: openapi.Response(description="Bad Request - Validation errors"),
            404: openapi.Response(description="Organization not found"),
            409: openapi.Response(description="Conflict - Email already exists"),
        },
        tags=['User Management']
    )
    def post(self, request, org_id):
        """Create a new user in the specified organization"""
        # Your existing implementation...
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
    """
    Internal Service API
    
    Secure endpoint for service-to-service communication. Requires HMAC authentication.
    """
    permission_classes = [ServiceTokenPermission]

    @swagger_auto_schema(
        operation_summary="Get User Info (Internal)",
        operation_description="""
        **Internal API - Service Authentication Required**
        
        Retrieve user information by email for service-to-service communication.
        
        ## Authentication Headers Required:
        - X-Service-Token: Service authentication token
        - X-Service-ID: Unique service identifier  
        - X-Timestamp: Unix timestamp (within 5 minutes)
        - X-Signature: HMAC-SHA256 signature
        
        ## Signature Generation:
        ```
        payload = "METHOD|PATH|BODY|SERVICE_ID|TIMESTAMP"
        signature = HMAC-SHA256(SERVICE_SECRET, payload)
        ```
        """,
        manual_parameters=[
            openapi.Parameter('email', openapi.IN_PATH, description="User email address", type=openapi.TYPE_STRING),
            openapi.Parameter('X-Service-Token', openapi.IN_HEADER, description="Service authentication token", type=openapi.TYPE_STRING, required=True),
            openapi.Parameter('X-Service-ID', openapi.IN_HEADER, description="Service identifier", type=openapi.TYPE_STRING, required=True),
            openapi.Parameter('X-Timestamp', openapi.IN_HEADER, description="Unix timestamp", type=openapi.TYPE_STRING, required=True),
            openapi.Parameter('X-Signature', openapi.IN_HEADER, description="HMAC signature", type=openapi.TYPE_STRING, required=True),
        ],
        responses={
            200: openapi.Response(
                description="User information retrieved successfully",
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'user_id': openapi.Schema(type=openapi.TYPE_STRING),
                        'org_id': openapi.Schema(type=openapi.TYPE_STRING),
                        'role': openapi.Schema(type=openapi.TYPE_STRING),
                    }
                )
            ),
            403: openapi.Response(description="Forbidden - Invalid service authentication"),
            404: openapi.Response(description="User not found"),
        },
        tags=['Internal APIs']
    )
    def get(self, request, email):
        """Internal API to get user information by email for auth service"""
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