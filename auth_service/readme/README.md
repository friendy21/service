# Authentication Service

A secure Django-based microservice for user authentication and JWT token management. This service handles user login, password verification, and provides JWT tokens with user organization information.

## Features

- **Secure Authentication**: Password hashing using Django's built-in bcrypt implementation
- **JWT Token Generation**: Issues JWT tokens with user and organization information
- **Microservice Integration**: Secure service-to-service communication with Organization Service
- **HMAC Authentication**: Service requests authenticated using HMAC-SHA256 signatures
- **Comprehensive Testing**: Full test coverage for models, views, services, and serializers
- **Request Logging**: Detailed logging for authentication attempts and service calls

## Architecture

The Authentication Service follows a clean architecture pattern:

```
authentication/
├── models/          # User data models
├── serializers/     # Request/response serialization
├── services/        # Business logic and external service communication
├── views/           # API endpoints
└── tests/           # Comprehensive test suite
```

## Quick Start

### Prerequisites

- Python 3.8+
- Django 5.2.1
- SQLite (default) or PostgreSQL/MySQL for production

### Installation

1. **Clone and navigate to the auth service directory**
2. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

3. **Set up environment variables (.env file):**
   ```env
   DEBUG=True
   DJANGO_SECRET_KEY=your-super-secret-django-key
   JWT_SECRET=your-super-secret-jwt-key
   ORG_SERVICE_URL=http://localhost:8001
   SERVICE_TOKEN=auth-service-token
   SERVICE_SECRET=shared-service-secret-key
   ALLOWED_HOSTS=localhost,127.0.0.1
   ```

4. **Run database migrations:**
   ```bash
   python manage.py makemigrations
   python manage.py migrate
   ```

5. **Start the development server:**
   ```bash
   python manage.py runserver 8000
   ```

## API Endpoints

### Authentication

#### POST /auth/login/

Authenticate user credentials and return JWT token.

**Request:**
```json
{
    "email": "user@example.com",
    "password": "userpassword"
}
```

**Success Response (200):**
```json
{
    "message": "Login successful",
    "token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9..."
}
```

**Error Responses:**
- `400 Bad Request`: Invalid request data
- `401 Unauthorized`: Invalid credentials
- `503 Service Unavailable`: Organization service unavailable

## JWT Token Structure

The service generates JWT tokens with the following payload:

```json
{
    "sub": "user_id",
    "email": "user@example.com",
    "org_id": "organization_id",
    "role": "member|admin|viewer",
    "exp": 1640995200,
    "iat": 1640991600,
    "iss": "auth-service"
}
```

## Service-to-Service Communication

The Authentication Service communicates securely with the Organization Service using HMAC-based authentication:

### Security Features

- **Service Token**: Identifies the calling service
- **HMAC Signature**: Prevents request tampering
- **Timestamp Validation**: Prevents replay attacks (5-minute window)
- **Request Signing**: All requests signed with service secret

### Signature Generation

```
payload = "METHOD|PATH|BODY|SERVICE_ID|TIMESTAMP"
signature = HMAC-SHA256(SERVICE_SECRET, payload)
```

## Database Schema

### AuthUser Model

```python
class AuthUser(models.Model):
    email = models.EmailField(unique=True, db_index=True)
    password = models.CharField(max_length=128)  # bcrypt hashed
    created_at = models.DateTimeField(auto_now_add=True)
```

**Features:**
- Email uniqueness constraint
- Indexed email field for fast lookups
- Secure password hashing with bcrypt
- Automatic timestamp tracking

## Testing

Run the comprehensive test suite:

```bash
# Run all tests
python manage.py test

# Run specific test modules
python manage.py test authentication.tests.test_models
python manage.py test authentication.tests.test_views
python manage.py test authentication.tests.test_services
python manage.py test authentication.tests.test_serializers

# Run with coverage
coverage run --source='.' manage.py test
coverage report -m
```

### Test Coverage

- **Models**: User creation, password hashing, uniqueness constraints
- **Views**: Login flow, error handling, authentication
- **Services**: User authentication, JWT generation, service communication
- **Serializers**: Data validation, normalization

## Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `DEBUG` | Enable debug mode | `True` |
| `DJANGO_SECRET_KEY` | Django secret key | Required |
| `JWT_SECRET` | JWT signing key | Required |
| `ORG_SERVICE_URL` | Organization service URL | `http://localhost:8001` |
| `SERVICE_TOKEN` | Service authentication token | Required |
| `SERVICE_SECRET` | HMAC signing secret | Required |
| `ALLOWED_HOSTS` | Allowed host names | `localhost,127.0.0.1` |

### Security Settings

- Password hashing using Django's PBKDF2 with SHA256
- JWT tokens expire after 1 hour
- Service requests must be made within 5 minutes of timestamp
- CORS configured for microservice communication

## Error Handling

The service provides detailed error responses:

- **400 Bad Request**: Invalid input data or validation errors
- **401 Unauthorized**: Authentication failures
- **500 Internal Server Error**: Unexpected server errors
- **503 Service Unavailable**: External service communication failures

## Logging

Comprehensive logging for security and debugging:

- Authentication attempts (success/failure)
- Service-to-service communication
- Error conditions and exceptions
- Performance metrics for external calls

## Production Considerations

### Security

1. **Environment Variables**: Store all secrets in environment variables
2. **HTTPS**: Use HTTPS in production
3. **Secret Rotation**: Regularly rotate JWT and service secrets
4. **Rate Limiting**: Implement rate limiting for login endpoints
5. **Monitoring**: Monitor authentication failures and service health

### Performance

1. **Database**: Use PostgreSQL or MySQL in production
2. **Connection Pooling**: Configure database connection pooling
3. **Caching**: Consider Redis for session management
4. **Load Balancing**: Deploy behind load balancer for high availability

### Monitoring

1. **Health Checks**: Implement health check endpoints
2. **Metrics**: Monitor authentication rates and response times
3. **Alerting**: Set up alerts for service failures
4. **Audit Logging**: Maintain audit logs for security compliance

## Dependencies

- **Django 5.2.1**: Web framework
- **djangorestframework 3.15.1**: API framework
- **PyJWT 2.8.0**: JWT token handling
- **requests 2.31.0**: HTTP client for service communication
- **bcrypt 4.1.2**: Password hashing
- **django-cors-headers 4.3.1**: CORS support
- **coverage 7.3.2**: Test coverage reporting