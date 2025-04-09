# Port Mapper Technical Architecture

This document describes the technical architecture of the Port Mapper application. It provides an overview of the system components, their interactions, and the data flows within the application.

## System Overview

Port Mapper is a Flask-based web application that processes CSV files containing server information and generates firewall port mapping requests based on exporter configurations and monitoring flags. The application features an intuitive web interface for uploading files, selecting servers, configuring ports, and generating output in various formats.

## Architecture Diagram

```
┌───────────────┐     ┌─────────────────┐     ┌───────────────┐
│ User Interface│     │ Flask Backend   │     │ Configuration │
│ (HTML/JS/CSS) │◄────┤ (app.py)        │◄────┤ (YAML)        │
└───────┬───────┘     └─────┬───────────┘     └───────────────┘
        │                   │                          ▲
        │                   │                          │
        ▼                   ▼                          │
┌───────────────┐     ┌─────────────────┐     ┌───────┴───────┐
│ File Upload   │     │ CSV Processing  │     │ Port Mappings │
└───────┬───────┘     └─────┬───────────┘     └───────────────┘
        │                   │                          ▲
        │                   │                          │
        ▼                   ▼                          │
┌───────────────┐     ┌─────────────────┐     ┌───────┴───────┐
│ Server Config │     │ Output Generator│─────┤ Format Engines │
└───────────────┘     └─────────────────┘     └───────────────┘
```

## Components

### 1. User Interface

The interface is built with HTML, CSS, and vanilla JavaScript:

- **index.html**: Home page with CSV upload form
- **process.html**: Server selection and port configuration interface
- **pdf_template.html**: Template for PDF output generation

**Key Features**:
- Responsive design for various screen sizes
- JavaScript-based form validation
- Dynamic port configuration interface
- Custom port mapping management with localStorage

### 2. Flask Backend

The core application is built on Flask:

- **Main Application (app.py)**: Contains all routes, request handlers, and processing logic
- **Configuration Loading**: Manages YAML configuration loading
- **Session Management**: Tracks uploaded files and user preferences

**Key Routes**:
- `/`: Home page with file upload
- `/process`: Server selection and configuration
- `/generate_output_csv`: Processes form submission
- `/api/port_mappings`: API for port mapping management

### 3. Configuration System

Configuration is managed through YAML files:

- **Default Configuration**: Built-in fallbacks
- **External Configuration**: Optional custom configuration via `PORT_CONFIG` environment variable
- **Session Configuration**: Custom port mappings stored in user's session

### 4. CSV Processing Engine

Complex CSV processing:

- **Header Detection**: Flexible detection of headers anywhere in first 10 rows
- **Data Extraction**: Case-insensitive column mapping
- **Exporter Identification**: Mapping exporters to known configurations
- **Edge Case Detection**: Identifying servers with special monitoring requirements

### 5. Port Mapping System

Management of port configurations:

- **Static Mappings**: Default port mappings for known exporters
- **Dynamic Mappings**: Custom mappings defined by users
- **Edge Case Handling**: Special handling for blackbox monitoring ports

### 6. Output Generation Engine

Multiple output formats:

- **CSV Generator**: Standard output
- **Excel Generator**: Using pandas
- **PDF Generator**: Using pdfkit and wkhtmltopdf
- **Firewall Format Generators**: Custom format generators for specific firewall types

## Data Flow

### 1. CSV Upload Flow

```
User → Upload Form → Flask Backend → Temporary Storage → Session → Redirect to Process Page
```

1. User selects a CSV file and provides MaaS-NG information
2. File is uploaded to a temporary location
3. File path and MaaS-NG info are stored in session
4. User is redirected to the process page

### 2. CSV Processing Flow

```
Stored CSV → Header Detection → Row Processing → Exporter Mapping → Edge Case Detection → Display
```

1. The uploaded CSV is read from temporary storage
2. Headers are detected using flexible matching
3. Each row is processed to extract server information
4. Exporters are mapped to known configurations
5. Edge cases (blackbox monitoring) are identified
6. All information is displayed for user selection

### 3. Port Configuration Flow

```
User Selection → Form Submission → Port Processing → Output Generation → File Download
```

1. User selects servers and configures ports
2. Form is submitted with selected options
3. Port configurations are processed and validated
4. Output is generated in the selected format
5. Generated file is sent to the user

### 4. Custom Port Mapping Flow

```
Port Mappings Tab → Custom Definition → localStorage → Session → CSV Generation
```

1. User accesses the Port Mappings tab
2. Custom exporter port mappings are defined
3. Mappings are stored in browser's localStorage
4. On form submission, mappings are sent to server
5. Server stores mappings in session
6. Mappings are used during CSV generation

## Key Algorithms

### 1. Flexible Header Detection

```python
# Look for the header row containing 'FQDN'
for i, row in enumerate(all_rows[:min(10, len(all_rows))]):
    if any('FQDN' in str(cell).upper() for cell in row):
        header_row = i
        logger.info(f"Found header row at line {header_row + 1}")
        break
```

### 2. Blackbox Monitoring Detection

```python
# Check SSH Banner
if ssh_banner_index is not None and ssh_banner_index < len(row):
    orig_value = row[ssh_banner_index].strip()
    value = orig_value.lower()
    if value in ('1', 'true', 'yes', 'y', 't'):
        monitoring_flags['ssh_banner'] = orig_value  # Keep original value
        if not has_exporters:
            is_edge_case = True
        logger.info(f"Detected SSH Banner for {row[fqdn_index]}: {orig_value}")
```

### 3. Port Conflict Resolution

```python
# TCP Connect monitoring
tcp_connect_port_key = f"tcp_connect_port_{target_fqdn}"
if tcp_connect_port_key in form_data:
    port = form_data[tcp_connect_port_key][0].strip()
    if port and port.lower() not in ('true', 'yes', '1', 't', 'y'):
        blackbox_ports.append(("TCP", port, "TCP Connect"))
    else:
        # Default or from TCP_Connect_Port
        port = tcp_port_value or "3389"
        blackbox_ports.append(("TCP", port, "TCP Connect"))
```

### 4. Duplicate Entry Prevention

```python
# Check for duplicates with blackbox monitoring entries
blackbox_port_entries = [(protocol, port) for protocol, port, _ in blackbox_ports]

# Filter out ports that match blackbox monitoring entries
unique_ports = [p for p in ports if not any(p == entry[1] for entry in blackbox_port_entries)]

# Add only unique entries
for port in unique_ports:
    entry = (maas_ng_fqdn, maas_ng_ip, target_fqdn, ip, "TCP", port, description)
    if entry not in unique_entries:
        writer.writerow(entry)
        unique_entries.add(entry)
```

## Data Storage

### 1. Session Storage

Flask's session is used to store:

- Path to the uploaded CSV file
- MaaS-NG information (FQDN and IP)
- Custom port mappings
- Edge case configurations

### 2. Client-Side Storage

Browser's localStorage is used to store:

- Custom port mappings defined in the Port Mappings tab

### 3. Temporary File Storage

Uploaded files are stored in:

- Default location: `/tmp/`
- Configurable via `UPLOAD_FOLDER` environment variable
- Files older than 1 hour are automatically cleaned up

## External Dependencies

### 1. Python Packages

- **Flask**: Web framework
- **Pandas**: Data manipulation for CSV and Excel
- **pdfkit**: PDF generation
- **PyYAML**: Configuration parsing

### 2. External Software

- **wkhtmltopdf**: Required for PDF generation
- **Docker**: For containerized deployment

## Performance Considerations

### 1. File Size Limits

- Maximum upload size is limited to 16MB
- Large files may require more memory and processing time

### 2. Concurrent Users

- No explicit concurrency handling
- Each user gets their own session
- Docker deployment improves isolation

### 3. Optimization Techniques

- Temporary file cleanup
- Unique entry tracking to avoid duplicates
- Session-based configuration to reduce database dependency

## Security Considerations

### 1. File Upload Security

- Filenames are sanitized using `secure_filename`
- File extensions are checked to ensure only CSV files are processed
- Temporary files have unique names using UUID

### 2. Session Security

- Flask secret key is used to encrypt session data
- Can be configured via `SECRET_KEY` environment variable

### 3. Input Validation

- Client-side validation for port inputs
- Server-side validation before processing

## Error Handling

### 1. User Input Errors

- Form validation with clear error messages
- Flash messages for server-side validation errors

### 2. Processing Errors

- Robust exception handling with informative messages
- Fallback to default configurations when custom settings fail

### 3. External Dependency Errors

- Graceful handling of missing wkhtmltopdf for PDF generation
- Fallback to CSV output when other formats fail

## Deployment Architecture

### 1. Docker Container

```
┌─────────────────────────────────────┐
│ Docker Container                    │
│                                     │
│  ┌───────────────┐ ┌─────────────┐  │
│  │ Flask App     │ │ wkhtmltopdf │  │
│  └───────┬───────┘ └─────────────┘  │
│          │                          │
│  ┌───────┴───────┐                  │
│  │ Temp Storage  │                  │
│  └───────────────┘                  │
└─────────────────────────────────────┘
```

- Self-contained image with all dependencies
- Exposed on port 5000
- Volume mounting for custom configuration

### 2. Production Deployment

Recommended production setup:

```
┌─────────────────┐     ┌─────────────────┐
│ Nginx/Apache    │     │ Docker Container │
│ Reverse Proxy   │────▶│ Port Mapper     │
└─────────────────┘     └─────────────────┘
```

- Reverse proxy for SSL termination and security
- Docker for isolation and easy updates
- Environment variables for configuration

## Extension Points

### 1. Adding New Exporters

New exporters can be added:

- Through YAML configuration
- Via the Port Mappings tab in the UI
- By updating the default port mappings in code

### 2. Adding New Output Formats

To add a new output format:

1. Add a new radio button option in process.html
2. Implement the format generator in app.py
3. Update the process_and_generate_output function to handle the new format

### 3. Custom Column Mappings

Column mappings can be extended in the YAML configuration:

```yaml
column_mappings:
  new_exporter:
    column_names:
      - "new_column_name"
      - "alternative_name"
```

## Conclusion

The Port Mapper application is designed with modularity and flexibility in mind. The architecture separates concerns between UI, processing logic, and output generation, making it easy to extend and maintain. The use of configuration files and session-based custom settings allows for easy customization without code changes.

For developers, the well-defined data flow and extension points make it straightforward to add new features or modify existing functionality while maintaining backward compatibility.