# portmapper.py
maps ips to used ports based on server monitoring functionality

    When the user navigates to the root URL (e.g., http://localhost:5000/), they will be served the index.html template, which displays a form to upload a CSV file and input the MaaS-NG IP address.

    The user fills in the MaaS-NG IP address and selects a CSV file to upload, then clicks the "Upload" button.

    The form data is sent as a POST request to the root URL. In the upload_csv() function, the Flask app checks if the file is present and if the MaaS-NG IP address is provided. If either is missing, it will flash an appropriate error message and redirect back to the form.

    If the file is uploaded and the MaaS-NG IP address is provided, the contents of the CSV file are stored in the user session and the user is redirected to the /process route with the MaaS-NG IP address as a query parameter.

    In the process() function, the Flask app reads the uploaded CSV file from the session and extracts the hostnames. It then renders the process.html template, which displays the hostnames and the MaaS-NG IP address, and allows the user to select the hostnames they want to include in the output CSV file.

    The user selects the hostnames they want to include and clicks the "Generate Output CSV" button.

    The form data is sent as a POST request to the /generate_output_csv route. The Flask app reads the uploaded CSV file from the session again, as well as the selected hostnames and MaaS-NG IP address from the form data.

    The create_port_csv() function is called with the provided input file, an empty StringIO object for the output file, the MaaS-NG IP address, and the selected hostnames. The function processes the input CSV file according to the port mappings and writes the result to the output file.

    After processing, the Flask app sends the output StringIO object as a CSV file to the user with the filename output.csv.

Throughout this process, the Flask application reads and processes the input CSV file, filters the hostnames based on user selection, and generates an output CSV file containing the port mappings.
