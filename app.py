import socket
from flask import Flask, render_template, request, Response

app = Flask(__name__)

# List of specified ports to scan based on requirements
PORTS_TO_SCAN = [21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445]

# Ports defined as high-risk
HIGH_RISK_PORTS = {21, 23, 445}

def is_valid_ip(ip):
    """ 
    Validates an IP address format using socket helper.
    Returns True if valid, False otherwise.
    """
    try:
        socket.inet_aton(ip)
        return True
    except socket.error:
        return False

def scan_ports(ip):
    """
    Scans the specific list of ports on the given IP address.
    Returns a tuple: (results_list, risk_level)
    """
    results = []
    has_open_ports = False
    has_high_risk = False
    
    for port in PORTS_TO_SCAN:
        status = "CLOSED"
        # Create a new socket for each connection attempt
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        
        # Use a 0.5 seconds timeout as requested
        sock.settimeout(0.5) 
        
        try:
            # connect_ex returns 0 if connection is successful
            result = sock.connect_ex((ip, port))
            if result == 0:
                status = "OPEN"
                has_open_ports = True
                
                # Check if this open port is classified as HIGH RISK
                if port in HIGH_RISK_PORTS:
                    has_high_risk = True
        except Exception:
            # Gracefully handle any unexpected socket errors without crashing
            status = "ERROR"
        finally:
            # Stability Rule: Always close sockets properly!
            sock.close()
            
        results.append({
            'port': port,
            'status': status,
            'is_high_risk': port in HIGH_RISK_PORTS
        })
        
    # Determine the overall Risk Classification
    if has_high_risk:
        risk_level = "HIGH"
    elif has_open_ports:
        risk_level = "MEDIUM"
    else:
        risk_level = "LOW"
        
    return results, risk_level

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        # Retrieve the target IP from the form submission
        target_ip = request.form.get('target_ip', '127.0.0.1')
        target_ip = target_ip.strip() # Remove any extra trailing spaces
        
        # Stability Feature: Validate IP address before attempting to scan
        if not is_valid_ip(target_ip):
            error_message = f"Invalid IP address format: '{target_ip}'. Please enter a valid IPv4 address."
            return render_template('index.html', error=error_message, default_ip=target_ip)
        
        # Stability Feature: Use try-except block to gracefully handle unexpected crashes
        try:
            results, risk_level = scan_ports(target_ip)
            return render_template('result.html', ip=target_ip, results=results, risk_level=risk_level)
        except Exception as e:
            error_message = f"An unexpected error occurred during scanning: {str(e)}"
            return render_template('index.html', error=error_message, default_ip=target_ip)
            
    # Regular GET request renders the default index page
    return render_template('index.html', default_ip='127.0.0.1')

@app.route('/download_report', methods=['POST'])
def download_report():
    """ Generates and returns a .txt report file for download """
    
    # Retrieve scan results from hidden form fields
    target_ip = request.form.get('target_ip', 'Unknown')
    risk_level = request.form.get('risk_level', 'Unknown')
    open_ports = request.form.get('open_ports', 'None')
    
    # Format the downloadable text file structure
    report_content = (
        "=======================================\n"
        "NetSentinel Security Scan Report\n"
        "=======================================\n"
        f"Target IP  : {target_ip}\n"
        f"Risk Level : {risk_level}\n"
        f"Open Ports : {open_ports}\n"
        "---------------------------------------\n"
        "Disclaimer: This tool is for authorized,\n"
        "educational, and ethical use only.\n"
        "=======================================\n"
    )

    # Respond with a text/plain file attachment
    return Response(
        report_content,
        mimetype="text/plain",
        headers={"Content-disposition": f"attachment; filename=netsentinel_report_{target_ip}.txt"}
    )

if __name__ == '__main__':
    # Start the Flask web application
    app.run(debug=True, host='127.0.0.1', port=5000)
