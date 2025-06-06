from rest_framework.views import exception_handler
from rest_framework.response import Response
from rest_framework import status
from django.db import DatabaseError, IntegrityError
import logging

logger = logging.getLogger(__name__)

def custom_exception_handler(exc, context):
    response = exception_handler(exc, context)
    
    if response is not None:
        return response

    # Handle database errors
    if isinstance(exc, IntegrityError):
        if 'unique_email' in str(exc).lower():
            return Response({
                "message": "User with this email already exists",
                "detail": "Email must be unique"
            }, status=status.HTTP_409_CONFLICT)
        
        logger.error(f"Database integrity error: {str(exc)}")
        return Response({
            "message": "Database constraint violation",
            "detail": str(exc)
        }, status=status.HTTP_400_BAD_REQUEST)
    
    if isinstance(exc, DatabaseError):
        logger.error(f"Database error: {str(exc)}")
        return Response({
            "message": "Database error",
            "detail": str(exc)
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    # Handle unexpected errors
    logger.error(f"Unexpected error: {str(exc)}")
    return Response({
        "message": "Internal server error",
        "detail": str(exc)
    }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)