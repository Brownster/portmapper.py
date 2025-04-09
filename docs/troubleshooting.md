# Port Mapper Troubleshooting Guide

This guide provides solutions to common issues encountered when working with the Port Mapper application. It's intended for developers and users troubleshooting problems with functionality, configuration, or deployment.

## Table of Contents

1. [CSV File Issues](#csv-file-issues)
2. [Port Configuration Issues](#port-configuration-issues)
3. [Output Generation Issues](#output-generation-issues)
4. [Deployment Issues](#deployment-issues)
5. [Edge Case Handling Issues](#edge-case-handling-issues)
6. [PDF Generation Issues](#pdf-generation-issues)
7. [Developer Environment Issues](#developer-environment-issues)

## CSV File Issues

### Issue: CSV Upload Fails

**Symptoms**: Upload completes but page reloads to upload form with an error, or no response.

**Possible Causes**:
- File too large (>16MB)
- File not actually a CSV format
- File extension incorrect
- CSV has invalid characters

**Solutions**:
1. Check file size and ensure it's under 16MB
2. Verify the file has a .csv extension
3. Open the file in a text editor to ensure it's valid CSV
4. Remove any non-standard characters or zero-width spaces

### Issue: CSV Headers Not Detected

**Symptoms**: Error message "Could not find FQDN column in the CSV file"

**Possible Causes**:
- Header row does not contain "FQDN" text
- Header row is beyond first 10 lines
- Character encoding issues

**Solutions**:
1. Ensure the CSV has a column with "FQDN" in the header
2. Move header row to one of the first 10 rows
3. Save the file with UTF-8 encoding
4. Check for hidden characters or spaces in the header names

### Issue: No Servers Displayed

**Symptoms**: Process page loads but no servers are listed.

**Possible Causes**:
- CSV file has headers but no data rows
- FQDN or IP columns are empty in all rows
- Data rows are malformed

**Solutions**:
1. Verify the CSV has data rows after the header
2. Check that FQDN and IP columns have values
3. Ensure commas are properly placed in CSV

## Port Configuration Issues

### Issue: Form Validation Errors

**Symptoms**: Error message when submitting the form about invalid port formats.

**Possible Causes**:
- Non-numeric characters in port fields
- Invalid special port values
- Comma formatting issues

**Solutions**:
1. Ensure port values are numeric or allowed special values (ping, true, etc.)
2. Format port lists with commas and no spaces: `22,443,8080`
3. Check if any port input has unexpected whitespace

### Issue: Custom Ports Not Applied

**Symptoms**: Output file doesn't contain custom port configurations.

**Possible Causes**:
- Ports entered but server not selected
- JavaScript validation preventing form submission
- Session data lost

**Solutions**:
1. Ensure the server checkbox is selected
2. Check browser console for JavaScript errors
3. Verify port formatting follows the expected pattern

### Issue: Boolean Values in Port Fields

**Symptoms**: Output file shows "TRUE" or "true" as port values.

**Possible Causes**:
- Boolean values from CSV being used as port numbers
- Default port not being applied correctly

**Solutions**:
1. Update to latest version with the fix for boolean port values
2. Manually clear the port field and enter numeric values

## Output Generation Issues

### Issue: Empty or Incomplete Output File

**Symptoms**: Output file downloads but is empty or missing entries.

**Possible Causes**:
- No servers selected
- Selected servers have no valid exporters
- Error during processing

**Solutions**:
1. Ensure at least one server is selected
2. Check if selected servers have valid exporters or monitoring flags
3. Check application logs for errors during processing

### Issue: Duplicate Port Entries

**Symptoms**: Output file contains duplicate entries for the same port.

**Possible Causes**:
- Multiple exporters using the same port
- Custom ports overlapping with default ports
- Edge case ports duplicating exporter ports

**Solutions**:
1. Update to latest version with duplicate detection
2. Review and modify custom port inputs
3. Remove redundant port values from input

## Deployment Issues

### Issue: Docker Container Won't Start

**Symptoms**: Container exits immediately after starting.

**Possible Causes**:
- Port conflict
- Incorrect environment variables
- Insufficient permissions

**Solutions**:
1. Check if port 5000 is already in use
2. Verify environment variables, especially PORT_CONFIG
3. Ensure the container has appropriate permissions

### Issue: Custom Configuration Not Loaded

**Symptoms**: Application uses default mappings instead of custom ones.

**Possible Causes**:
- Incorrect file path
- File permissions issues
- YAML syntax errors

**Solutions**:
1. Double-check the file path when using PORT_CONFIG
2. Verify YAML syntax is valid
3. When using Docker, ensure the file is properly mounted

## Edge Case Handling Issues

### Issue: Edge Cases Not Detected

**Symptoms**: Servers with monitoring flags aren't highlighted as edge cases.

**Possible Causes**:
- Monitoring flags not in expected format
- Column headers not recognized
- Server also has exporters (hybrid case)

**Solutions**:
1. Verify monitoring flags use recognized values (TRUE, true, yes, 1)
2. Check column headers for correct naming
3. Remember that servers with both exporters and monitoring flags aren't marked as edge cases

### Issue: Default Ports Not Applied

**Symptoms**: Edge case servers missing expected default ports.

**Possible Causes**:
- Monitoring flags not detected
- Custom port field overriding defaults
- Template changes

**Solutions**:
1. Verify the monitoring flags are in the expected columns
2. Check if custom ports are being applied
3. Update to the latest version with fixes for default port handling

## PDF Generation Issues

### Issue: PDF Generation Fails

**Symptoms**: Error message when selecting PDF format, or falls back to CSV.

**Possible Causes**:
- wkhtmltopdf not installed
- wkhtmltopdf path not found
- Dependencies missing

**Solutions**:
1. Install wkhtmltopdf using package manager
2. When using Docker, ensure the official image is used
3. Check application logs for specific wkhtmltopdf errors

### Issue: PDF Formatting Problems

**Symptoms**: PDF generates but content is cut off or poorly formatted.

**Possible Causes**:
- Too many columns or rows
- Custom CSS issues
- wkhtmltopdf version incompatibility

**Solutions**:
1. Limit the number of selected servers
2. Try a different output format (Excel or CSV)
3. Update wkhtmltopdf to the latest version

## Developer Environment Issues

### Issue: Tests Failing

**Symptoms**: pytest fails with errors.

**Possible Causes**:
- Missing dependencies
- Code changes breaking tests
- Environment differences
- Missing test files (`test_app_coverage.py` not found)

**Solutions**:
1. Install all dependencies from requirements.txt
2. Update tests to match code changes
3. Check for environment-specific paths or settings
4. Ensure all test files are committed to the repository

### Issue: Linting Errors

**Symptoms**: pylint reports errors.

**Possible Causes**:
- Code style violations
- New Python version with stricter rules
- Custom pylint config
- Variable shadowing in nested loops (undefined loop variable)

**Solutions**:
1. Run `pylint $(git ls-files '*.py')` to see all errors
2. Fix style issues according to PEP 8
3. Update .pylintrc if needed for project-specific rules
4. For undefined loop variable errors:
   - Use different variable names in nested loops (e.g., `data_row`, `search_row`)
   - Avoid reusing the same variable name in different loop scopes
   - Be careful with nested loops that reference outer loop variables

## Common Error Messages and Solutions

| Error Message | Likely Cause | Solution |
|---------------|--------------|----------|
| "Could not find FQDN column in the CSV file" | Header row missing or incorrect | Ensure CSV has a column with "FQDN" in the header |
| "No valid hostnames found in the uploaded CSV" | CSV data incomplete | Verify CSV has valid data in FQDN and IP columns |
| "Invalid port format" | Non-numeric or invalid port value | Use only numbers, "ping", or recognized boolean values |
| "wkhtmltopdf not found" | PDF dependency missing | Install wkhtmltopdf or use Docker image |
| "File too large" | CSV exceeds size limit | Reduce file size or increase MAX_CONTENT_LENGTH |
| "Error processing CSV" | Various CSV parsing issues | Check CSV format, encoding, and structure |

## Checking Application Logs

For troubleshooting more complex issues, check the application logs:

1. **Local deployment**: 
   - Check `app.log` in the application directory
   - Monitor console output when running directly

2. **Docker deployment**:
   ```bash
   docker logs <container_id>
   ```

3. **Production deployment**:
   - Check the configured log location
   - If using systemd: `journalctl -u portmapper`

## Contacting Support

If you encounter issues not covered in this guide:

1. Check the [GitHub Issues](https://github.com/Brownster/portmapper.py/issues) for similar problems
2. Open a new issue with:
   - Detailed description of the problem
   - Steps to reproduce
   - Error messages and logs
   - Version information

## Updating the Application

To update to the latest version with bug fixes:

1. **Docker**:
   ```bash
   docker pull brownster/portmapper:latest
   ```

2. **Git**:
   ```bash
   git pull origin main
   pip install -r requirements.txt
   ```