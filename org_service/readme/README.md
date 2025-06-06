# Organization Service

A Django-based microservice for managing organizations and users. This service provides both public APIs for user management and secure internal APIs for service-to-service communication with the Authentication Service.

## Features

- **Organization Management**: Create and manage organizations
- **User Management**: Create users within organizations with role-based access
- **Service-to-Service Security**: HMAC-based authentication for internal APIs
- **Role-Based Access Control**: Support for admin, member, and viewer roles
- **Comprehensive Testing**: Full test coverage including security and edge cases
- **Request Logging**: Detailed logging for internal API calls and security monitoring
- **Custom Exception Handling**: Graceful error handling with detailed responses

## Architecture

The Organization Service follows a clean architecture pattern with clear separation of concerns:

```
organizations/
├── models/          # Data models for organizations and users
├── serializers/     # Request/response serialization
├── views/           # API endpoints (public and internal)
├── permissions.py   # Service-to-service authentication
├── middleware/      # Request logging and monitoring
├── exceptions/      # Custom exception handling
└── tests/           # Comprehensive test suite
```

## Quick Start

### Prerequisites

- Python 3.8+
- Django 5.2.1
- SQLite (default) or PostgreSQL/MySQL for production

### Installation

1. **Clone and navigate to the org service directory**
2. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

3. **Set up environment variables (.env file):**
   ```env
   DEBUG=True
   DJANGO_SECRET_KEY=your-super-secret-django-key
   SERVICE_TOKEN=org-service-token
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
   python manage.py runserver 8001
   ```
   - Swagger UI: http://localhost:8001/swagger/

## API Endpoints
Organization Management
- `POST   /organization/` — Create organization
- `GET    /organization/<uuid:pk>/` — Retrieve organization
- `GET    /organization/list/` — List organizations
- `PUT    /organization/<uuid:pk>/update/` — Update organization
- `DELETE /organization/<uuid:pk>/delete/` — Delete organization

Data Source Configuration
- `POST   /datasource/` — Create data source config
- `GET    /datasource/<int:pk>/` — Retrieve data source config
- `GET    /datasource/list/ — List data` source configs
- `PUT    /datasource/<int:pk>/update/` — Update data source config
- `DELETE /datasource/<int:pk>/delete/` — Delete data source config
- `POST   /datasource/<int:pk>/connect/` — Connect data source

### Public APIs

#### POST /orgs/{org_id}/users/

Create a new user in the specified organization.

**Request:**
```json
{
    "email": "user@example.com",
    "name": "John Doe",
    "role": "member"
}
```

**Success Response (201):**
```json
{
    "message": "User account created successfully",
    "user_id": "550e8400-e29b-41d4-a716-446655440000",
    "email": "user@example.com",
    "org_id": "550e8400-e29b-41d4-a716-446655440001",
    "role": "member"
}
```

**Error Responses:**
- `400 Bad Request`: Invalid request data or validation errors
- `404 Not Found`: Organization not found
- `409 Conflict`: Email already exists

### Internal APIs (Service-to-Service)

#### GET /internal/users/{email}/

Retrieve user information by email for authentication service.

**Authentication Required**: Service token and HMAC signature

**Success Response (200):**
```json
{
    "user_id": "550e8400-e29b-41d4-a716-446655440000",
    "org_id": "550e8400-e29b-41d4-a716-446655440001",
    "role": "member"
}
```

**Error Responses:**
- `403 Forbidden`: Invalid service authentication
- `404 Not Found`: User not found

## Data Models

### Organization Model

```python
class Organization(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=255)
    email = models.EmailField()
    phone = models.CharField(max_length=20, null=True, blank=True)
    address = models.CharField(max_length=255, null=True, blank=True)
    website = models.URLField(null=True, blank=True)
    industry = models.CharField(max_length=100, null=True, blank=True)
    size = models.IntegerField(null=True, blank=True)
    owner_id = models.UUIDField(null=True, blank=True)
    created_at = models.DateTimeField(default=timezone.now)
    updated_at = models.DateTimeField(auto_now=True)
    is_active = models.BooleanField(default=True)
```

### OrgUser Model

```python
class OrgUser(models.Model):
    ROLE_CHOICES = [
        ('admin', 'Administrator'),
        ('member', 'Member'),
        ('viewer', 'Viewer'),
    ]
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4)
    email = models.EmailField(unique=True, db_index=True)
    name = models.CharField(max_length=255)
    role = models.CharField(max_length=20, choices=ROLE_CHOICES)
    org = models.ForeignKey(Organization, on_delete=models.CASCADE)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
```

### DataSourceConfig Model

```python
class DataSourceConfig(models.Model):
    SERVICE_CHOICES = [
        ('microsoft_365', 'Microsoft 365'),
        ('google_workspace', 'Google Workspace'),
        ('dropbox', 'DropBox'),
        ('slack', 'Slack'),
        ('zoom', 'Zoom'),
        ('jira', 'Jira'),
    ]

    STATUS_CHOICES = [
        ('not_connected', 'Not Connected'),
        ('connected', 'Connected'),
        ('invalid_credentials', 'Invalid Credentials'),
        ('insufficient_permissions', 'Insufficient Permissions'),
        ('connection_error', 'Connection Error'),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    service_name = models.CharField(max_length=100, choices=SERVICE_CHOICES)
    tenant_id = models.CharField(max_length=255, blank=True, null=True)

    description = models.TextField(blank=True, null=True)
    api_endpoint = models.CharField(max_length=255)
    auth_type = models.CharField(max_length=50)

    client_id = models.CharField(max_length=255, blank=True, null=True)
    client_secret = models.CharField(max_length=255, blank=True, null=True)
    api_key = models.CharField(max_length=255, blank=True, null=True)
    scopes = models.TextField(blank=True, null=True)

    created_at = models.DateTimeField(default=timezone.now)
    updated_at = models.DateTimeField(auto_now=True)

    organisation = models.ForeignKey(
        'Organization',
        on_delete=models.CASCADE,
        related_name='data_source_configs'
    )
```

**Key Features:**
- UUID primary keys for security
- Global email uniqueness across all organizations
- Indexed fields for optimal query performance
- Role-based access control
- Audit timestamps

## Service-to-Service Authentication

The Organization Service implements robust HMAC-based authentication for internal APIs:

### Security Components

1. **Service Token**: Identifies the calling service
2. **Service ID**: Unique identifier for the requesting service
3. **Timestamp**: Prevents replay attacks (5-minute tolerance window)
4. **HMAC Signature**: Ensures request integrity and authenticity

### Authentication Headers

```
X-Service-Token: auth-service-token
X-Service-ID: auth-service
X-Timestamp: 1640991600
X-Signature: a1b2c3d4e5f6...
```

### Signature Generation

```python
payload = f"{METHOD}|{PATH}|{BODY}|{SERVICE_ID}|{TIMESTAMP}"
signature = HMAC-SHA256(SERVICE_SECRET, payload)
```

### Security Features

- **Replay Attack Prevention**: Timestamp validation within 5-minute window
- **Request Integrity**: HMAC signature verification
- **Service Identification**: Token-based service authentication
- **Audit Logging**: All internal API calls logged for security monitoring

## Role-Based Access Control

The service supports three user roles:

| Role | Description | Permissions |
|------|-------------|-------------|
| `admin` | Administrator | Full access to organization resources |
| `member` | Regular Member | Standard user permissions |
| `viewer` | Read-Only | View-only access to resources |

## Testing

Run the comprehensive test suite:

```bash
# Run all tests
python manage.py test

# Run specific test modules
python manage.py test organizations.tests.test_models
python manage.py test organizations.tests.test_views
python manage.py test organizations.tests.test_permissions
python manage.py test organizations.tests.test_serializers

# Run with coverage
coverage run --source='.' manage.py test
coverage report -m
```

### Test Coverage Areas

- **Models**: Data validation, constraints, relationships
- **Views**: API endpoints, error handling, edge cases
- **Permissions**: Service authentication, security validation
- **Serializers**: Data validation, normalization, transformation
- **Middleware**: Request logging, monitoring
- **Exceptions**: Custom error handling

## Request Logging and Monitoring

### Service Logging Middleware

The service includes comprehensive logging for internal API calls:

```python
class ServiceLoggingMiddleware:
    """
    Logs all internal service API calls for security monitoring
    """
```

**Logged Information:**
- Service ID and client IP
- Request method and path
- Response status and duration
- Authentication status

**Sample Log Output:**
```
Internal API call: GET /internal/users/user@example.com/ from service=auth-service ip=127.0.0.1
Internal API response: 200 for service=auth-service duration=0.045s
```

## Error Handling

### Custom Exception Handler

The service provides detailed, consistent error responses:

```python
def custom_exception_handler(exc, context):
    """
    Custom exception handler for consistent error responses
    """
```

**Error Response Format:**
```json
{
    "message": "Human-readable error message",
    "detail": "Technical details for debugging"
}
```

**Handled Exception Types:**
- Database integrity errors
- Validation errors
- Service authentication failures
- Unexpected server errors

## Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `DEBUG` | Enable debug mode | `True` |
| `DJANGO_SECRET_KEY` | Django secret key | Required |
| `SERVICE_TOKEN` | Service authentication token | Required |
| `SERVICE_SECRET` | HMAC signing secret | Required |
| `ALLOWED_HOSTS` | Allowed host names | `localhost,127.0.0.1` |

### Database Configuration

**Development:**
- SQLite database (default)
- In-memory database for testing
- Optimized for development speed

**Production Considerations:**
- PostgreSQL or MySQL recommended
- Connection pooling for performance
- Read replicas for scaling

## Security Features

### Data Protection

1. **UUID Primary Keys**: Prevents ID enumeration attacks
2. **Email Uniqueness**: Global email constraints across organizations
3. **Input Validation**: Comprehensive data validation and sanitization
4. **SQL Injection Protection**: Django ORM provides built-in protection

### Service Security

1. **HMAC Authentication**: Cryptographically secure service authentication
2. **Timestamp Validation**: Prevents replay attacks
3. **Request Logging**: Security audit trail for all internal calls
4. **CORS Configuration**: Properly configured cross-origin settings

### Concurrency Control

1. **Database Transactions**: Atomic operations for data consistency
2. **Row-Level Locking**: Prevents race conditions in user creation
3. **Select for Update**: Ensures data integrity under concurrent access

## Performance Optimizations

### Database Indexes

Strategic indexing for optimal query performance:

```python
class Meta:
    indexes = [
        models.Index(fields=['email']),           # User lookups
        models.Index(fields=['org', 'role']),     # Role-based queries
        models.Index(fields=['created_at']),      # Temporal queries
    ]
```

### Query Optimization

- **Select Related**: Minimize database queries for related objects
- **Bulk Operations**: Efficient handling of multiple records
- **Connection Pooling**: Reuse database connections

## Production Deployment

### Security Checklist

- [ ] Use strong, unique secrets for all environment variables
- [ ] Enable HTTPS with proper SSL certificates
- [ ] Configure proper CORS settings for production domains
- [ ] Set up rate limiting for public APIs
- [ ] Implement comprehensive monitoring and alerting
- [ ] Regular security audits and dependency updates

### Monitoring and Observability

1. **Health Checks**: Implement service health endpoints
2. **Metrics Collection**: Monitor API response times and error rates
3. **Log Aggregation**: Centralized logging for security and debugging
4. **Alerting**: Real-time alerts for service failures and security events

### Scaling Considerations

1. **Load Balancing**: Deploy behind application load balancer
2. **Database Scaling**: Read replicas and connection pooling
3. **Caching**: Redis for session and query caching
4. **Service Mesh**: Consider service mesh for complex deployments

## Dependencies

- **Django 5.2.1**: Web framework
- **djangorestframework 3.15.1**: API framework  
- **django-cors-headers 4.3.1**: CORS support
- **coverage 7.3.2**: Test coverage reporting
- **drf-yasg 1.21.7**: Swagger/OpenAPI documentation generation  
- **python-dotenv 1.0.1**: Environment variable management  
- **requests 2.31.0**: HTTP client for external API calls

## Integration with Authentication Service

The Organization Service seamlessly integrates with the Authentication Service:

1. **User Creation**: Public API for creating users in organizations
2. **User Lookup**: Internal API for authentication service queries
3. **Role Information**: Provides user roles for JWT token generation
4. **Security**: Mutual HMAC-based authentication between services

This integration enables the Authentication Service to generate JWT tokens with complete user and organization context while maintaining service boundaries and security.