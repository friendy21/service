# Microsoft Extraction System: Flask & Django Integration

This system provides robust email extraction from Microsoft Outlook mailboxes using both a Flask backend (for extraction logic) and a Django API (for orchestration and integration with other services).

---

## Overview
- **Flask Server**: Handles the actual extraction, pausing, continuing, and cancelling of email extraction jobs. Communicates with Microsoft Graph API and the database.
- **Django Server**: Provides a REST API for clients, manages requests, and forwards them to the Flask server. Also provides Swagger UI for easy testing.

---

## Running the Servers

### 1. Flask Server
```
cd extractions/microsoft/OutlookMail
python app.py
```
- Runs on: `http://localhost:3006`

### 2. Django Server
```
cd root/organization
python manage.py runserver
```
- Runs on: `http://localhost:8000`
- Swagger UI: `http://localhost:8000/swagger/`

---

## Flask API Endpoints for email extraction

### Single User Extraction
- `POST /api/emails/extract/start/<connection_id>`
- `POST /api/emails/extract/pause/<connection_id>`
- `POST /api/emails/extract/continue/<connection_id>`
- `POST /api/emails/extract/cancel/<connection_id>`
- `GET /api/emails/extract/status/<connection_id>`
- `GET /api/emails/extract/result/<connection_id>`

### Batch Extraction
- `POST /api/emails/extract/batch/start`
- `POST /api/emails/extract/batch/pause/<batch_id>`
- `POST /api/emails/extract/batch/continue/<batch_id>`
- `POST /api/emails/extract/batch/cancel/<batch_id>`
- `GET /api/emails/extract/batch/status/<batch_id>`
- `GET /api/emails/extract/batch/result/<batch_id>`

---



## Integration Notes
- The Django server acts as a proxy and orchestrator, forwarding requests to the Flask server.
- Both servers must be running for the system to function.
- Use the Django Swagger UI for easy API testing.
- All configuration (tenant ID, client ID, client secret) can be provided in the request body or as environment variables.
- Pausing and continuing works even after a server restart, as long as the store file is preserved (tracked by connection_id or batch_id).
- Cancelled or completed tasks cannot be resumed.

---

For more details, see the code and comments in the respective `services.py`, `app.py`, and Django view/serializer files.

# Organization Django API

This Django app provides a REST API for managing organizations, data sources, and email extraction tasks. It integrates with a Flask backend for Outlook email extraction.

---

## Django API Endpoints

### Organization Management
- `POST   /organization/` — Create organization
- `GET    /organization/<uuid:pk>/` — Retrieve organization
- `GET    /organization/list/` — List organizations
- `PUT    /organization/<uuid:pk>/update/` — Update organization
- `DELETE /organization/<uuid:pk>/delete/` — Delete organization

### Data Source Configuration
- `POST   /datasource/` — Create data source config
- `GET    /datasource/<int:pk>/` — Retrieve data source config
- `GET    /datasource/list/` — List data source configs
- `PUT    /datasource/<int:pk>/update/` — Update data source config
- `DELETE /datasource/<int:pk>/delete/` — Delete data source config
- `POST   /datasource/<int:pk>/connect/` — Connect data source

### Extraction (Generic)
- `POST   /extract/<uuid:pk>/start/` — Start extraction
- `GET    /extract/<uuid:pk>/status/` — Get extraction status
- `GET    /extract/<uuid:pk>/result/` — Get extraction result

### Email Extraction (Outlook)
- `POST   /email-extract/start/<str:connection_id>/` — Start single user extraction
- `GET    /email-extract/status/<str:connection_id>/` — Get single extraction status
- `GET    /email-extract/result/<str:connection_id>/` — Get single extraction result
- `POST   /email-extract/batch/start/` — Start batch extraction
- `GET    /email-extract/batch/status/<str:batch_id>/` — Get batch extraction status
- `GET    /email-extract/batch/result/<str:batch_id>/` — Get batch extraction result
- `POST   /email-extract/pause/<str:connection_id>/` — Pause single extraction
- `POST   /email-extract/continue/<str:connection_id>/` — Continue single extraction
- `POST   /email-extract/cancel/<str:connection_id>/` — Cancel single extraction
- `POST   /email-extract/batch/pause/<str:batch_id>/` — Pause batch extraction
- `POST   /email-extract/batch/continue/<str:batch_id>/` — Continue batch extraction
- `POST   /email-extract/batch/cancel/<str:batch_id>/` — Cancel batch extraction

---

For more details, see the code in `views/` and `serializers/` directories.
