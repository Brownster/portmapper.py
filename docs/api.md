# Port Mapper API Documentation

This document describes the API endpoints provided by the Port Mapper application.

## Overview

Port Mapper includes a simple API for managing port mappings. This API allows for retrieving the current port mappings and setting custom port mappings.

## Authentication

Currently, the API does not require authentication as it's designed for use within the web application. For production deployments, consider adding authentication if exposing the API externally.

## API Endpoints

### Get Port Mappings

Retrieves the current port mappings configuration.

**URL**: `/api/port_mappings`

**Method**: `GET`

**Response Format**: JSON

**Example Response**:
```json
{
  "exporter_linux": {
    "src": [["TCP", "22"], ["ICMP", "ping"]],
    "dst": []
  },
  "exporter_windows": {
    "src": [["TCP", "9182"], ["ICMP", "ping"]],
    "dst": [["UDP", "514"], ["TCP", "514"]]
  }
}
```

### Set Custom Port Mappings

Sets custom port mappings for the current session.

**URL**: `/api/port_mappings`

**Method**: `POST`

**Request Format**: JSON

**Example Request**:
```json
{
  "exporter_custom": {
    "src": [["TCP", "8080"], ["TCP", "9090"]],
    "dst": [["TCP", "7070"]]
  }
}
```

**Example Response**:
```json
{
  "status": "success",
  "message": "Saved 1 custom port mappings"
}
```

## Error Handling

API errors are returned as JSON objects with a status and message:

```json
{
  "status": "error",
  "message": "Error message details"
}
```

Common HTTP status codes:
- 200: Success
- 400: Bad request (invalid JSON, missing fields)
- 405: Method not allowed (using an unsupported HTTP method)
- 500: Server error

## Data Formats

### Port Mapping Object

Port mappings follow this structure:

```json
{
  "exporter_name": {
    "src": [["PROTOCOL", "PORT"], ...],
    "dst": [["PROTOCOL", "PORT"], ...]
  }
}
```

Where:
- `exporter_name`: String identifier for the exporter (e.g., "exporter_linux")
- `src`: Array of protocol/port pairs for monitoring server to target
- `dst`: Array of protocol/port pairs for target to monitoring server
- `PROTOCOL`: String protocol identifier ("TCP", "UDP", "ICMP")
- `PORT`: String port number or "ping" for ICMP

## Implementation Details

The API endpoints are implemented in the `port_mappings_api()` function in `app.py`. Custom port mappings are stored in the Flask session and merged with the default mappings during CSV generation.

## Future Enhancements

Planned API enhancements:
- Authentication for API access
- Permanent storage of custom mappings
- Additional endpoints for managing other settings
- Versioned API endpoints