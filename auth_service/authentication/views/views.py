from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from authentication.serializers.serializers import LoginSerializer
from authentication.services.services import AuthenticationService
import logging

logger = logging.getLogger(__name__)

class LoginView(APIView):
    def __init__(self):
        super().__init__()
        self.auth_service = AuthenticationService()

    def post(self, request):
        """
        Authenticate user and return JWT token
        """
        try:
            # Validate request data
            serializer = LoginSerializer(data=request.data)
            if not serializer.is_valid():
                return Response({
                    "message": "Invalid request data",
                    "errors": serializer.errors
                }, status=status.HTTP_400_BAD_REQUEST)

            email = serializer.validated_data['email']
            password = serializer.validated_data['password']

            # Authenticate user credentials
            auth_user = AuthenticationService.authenticate_user(email, password)
            if not auth_user:
                logger.warning(f"Authentication failed for user: {email}")
                return Response({
                    "message": "Invalid credentials"
                }, status=status.HTTP_401_UNAUTHORIZED)

            # Get user organization information using secure service client
            try:
                org_info = self.auth_service.get_user_org_info(email)
            except Exception as e:
                logger.error(f"Failed to get org info for {email}: {str(e)}")
                return Response({
                    "message": "Service unavailable",
                    "detail": str(e)
                }, status=status.HTTP_503_SERVICE_UNAVAILABLE)

            # Generate JWT token
            token = AuthenticationService.generate_jwt_token(
                email=email,
                user_id=org_info['user_id'],
                org_id=org_info['org_id'],
                role=org_info['role']
            )

            logger.info(f"Successful login for user: {email}")
            return Response({
                "message": "Login successful",
                "token": token
            }, status=status.HTTP_200_OK)

        except Exception as e:
            logger.error(f"Unexpected error during login: {str(e)}")
            return Response({
                "message": "Internal server error",
                "detail": str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)