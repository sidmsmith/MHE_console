# api/index.py
from flask import Flask, request, jsonify, send_from_directory
import json
import os
import requests
from requests.auth import HTTPBasicAuth
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

app = Flask(__name__)

# === SECURE CONFIG (from Vercel Environment Variables) ===
HA_WEBHOOK_URL = os.getenv("HA_WEBHOOK_URL", "http://sidmsmith.zapto.org:8123/api/webhook/mhe_console")
HA_HEADERS = {"Content-Type": "application/json"}

AUTH_HOST = "salep-auth.sce.manh.com"
API_HOST = "salep.sce.manh.com"
USERNAME_BASE = "sdtadmin@"
PASSWORD = os.getenv("MANHATTAN_PASSWORD")
CLIENT_ID = "omnicomponent.1.0.0"
CLIENT_SECRET = os.getenv("MANHATTAN_SECRET")

# Critical: Fail fast if secrets missing
if not PASSWORD or not CLIENT_SECRET:
    raise Exception("Missing MANHATTAN_PASSWORD or MANHATTAN_SECRET environment variables")

# === HELPERS ===
def send_ha_message(payload):
    try:
        requests.post(HA_WEBHOOK_URL, json=payload, headers=HA_HEADERS, timeout=5)
    except:
        pass

def get_manhattan_token(org):
    url = f"https://{AUTH_HOST}/oauth/token"
    username = f"{USERNAME_BASE}{org.lower()}"
    data = {
        "grant_type": "password",
        "username": username,
        "password": PASSWORD
    }
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    auth = HTTPBasicAuth(CLIENT_ID, CLIENT_SECRET)
    try:
        r = requests.post(url, data=data, headers=headers, auth=auth, timeout=60, verify=False)
        if r.status_code == 200:
            return r.json().get("access_token")
    except Exception as e:
        print(f"[AUTH] Error: {e}")
    return None

# === API ROUTES ===
@app.route('/api/app_opened', methods=['POST'])
def app_opened():
    send_ha_message({"event": "mhe_console_open"})
    return jsonify({"success": True})

@app.route('/api/auth', methods=['POST'])
def auth():
    org = request.json.get('org', '').strip()
    if not org:
        return jsonify({"success": False, "error": "ORG required"})
    token = get_manhattan_token(org)
    if token:
        send_ha_message({"event": "mhe_console_auth", "org": org, "success": True})
        return jsonify({"success": True, "token": token})
    send_ha_message({"event": "mhe_console_auth", "org": org, "success": False})
    return jsonify({"success": False, "error": "Auth failed"})

# === MHE MESSAGE GENERATION AND SENDING ===
# Based on Postman collection: All messages use the same endpoint with different formats

MHE_ENDPOINT_ID = "WCSTestingEndpoint"
ENDPOINT_STATUS_PATH = "/device-integration/api/deviceintegration/service/endpoint/status"
ENDPOINT_START_PATH = "/device-integration/api/deviceintegration/service/endpoint/start"
ENDPOINT_STOP_PATH = "/device-integration/api/deviceintegration/service/endpoint/stop"
MHE_API_PATH = "/device-integration/api/deviceintegration/process"
ILPN_SEARCH_PATH = "/dcinventory/api/dcinventory/ilpn/search"
LOCATION_SEARCH_PATH = "/dcinventory/api/dcinventory/location/search"
OLPN_SEARCH_PATH = "/pickpack/api/pickpack/olpn/search"

def parse_lpns(input_text):
    """
    Parse multiple LPNs from input text.
    Supports spaces, commas, and semicolons as separators.
    Case-sensitive - no upper/lower case adjustments.
    """
    if not input_text:
        return []
    # Split by common delimiters (space, comma, semicolon)
    import re
    # Split on spaces, commas, or semicolons, then filter out empty strings
    lpns = re.split(r'[,\s;]+', input_text.strip())
    # Filter out empty strings and strip whitespace
    lpns = [lpn.strip() for lpn in lpns if lpn.strip()]
    return lpns

def parse_lpn_location_pairs(input_text):
    """
    Parse LPN,Location pairs from input text.
    Format: "LPN1,Location1; LPN2,Location2" or "LPN1,Location1;LPN2,Location2"
    Semicolons separate pairs, commas separate LPN from Location within each pair.
    Case-sensitive - no upper/lower case adjustments.
    Returns: List of dicts with 'lpn' and 'location' keys
    """
    if not input_text:
        return []
    
    pairs = []
    # First split by semicolon to get pairs
    pair_strings = [p.strip() for p in input_text.split(';') if p.strip()]
    
    for pair_str in pair_strings:
        # Split each pair by comma to get LPN and Location
        parts = [p.strip() for p in pair_str.split(',') if p.strip()]
        if len(parts) == 2:
            pairs.append({'lpn': parts[0], 'location': parts[1]})
        elif len(parts) == 1:
            # If only one part, treat as LPN with empty location (will be validated)
            pairs.append({'lpn': parts[0], 'location': ''})
        # If more than 2 parts, skip (invalid format)
    
    return pairs

def parse_lpn_shipment_pairs(input_text):
    """
    Parse LPN,Shipment pairs from input text.
    Format: "LPN1,Shipment1; LPN2,Shipment2" or "LPN1,Shipment1;LPN2,Shipment2"
    Semicolons separate pairs, commas separate LPN from Shipment within each pair.
    Case-sensitive - no upper/lower case adjustments.
    Returns: List of dicts with 'lpn' and 'shipment' keys
    """
    if not input_text:
        return []
    
    pairs = []
    # First split by semicolon to get pairs
    pair_strings = [p.strip() for p in input_text.split(';') if p.strip()]
    
    for pair_str in pair_strings:
        # Split each pair by comma to get LPN and Shipment
        parts = [p.strip() for p in pair_str.split(',') if p.strip()]
        if len(parts) == 2:
            pairs.append({'lpn': parts[0], 'shipment': parts[1]})
        elif len(parts) == 1:
            # If only one part, treat as LPN with empty shipment (will be validated)
            pairs.append({'lpn': parts[0], 'shipment': ''})
        # If more than 2 parts, skip (invalid format)
    
    return pairs

def validate_lpns(org, token, lpns, required_status='1000', log_callback=None):
    """
    Validate that LPNs exist and have the required status.
    Returns: {
        'valid': [list of valid LPNs],
        'invalid': [list of invalid LPNs],
        'errors': [list of error messages],
        'request_payload': payload sent,
        'response': response received,
        'lpn_data': {lpn: {TotalQuantity: value, ...}}  # Map of LPN to its data from API
    }
    """
    if not lpns:
        return {'valid': [], 'invalid': [], 'errors': [], 'request_payload': None, 'response': None, 'lpn_data': {}}
    
    url = f"https://{API_HOST}{ILPN_SEARCH_PATH}"
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
        "selectedOrganization": org.upper(),
        "selectedLocation": f"{org.upper()}-DM1"
    }
    
    # Build query: IlpnId = 'LPN1' OR IlpnId = 'LPN2' OR ...
    query_parts = [f"IlpnId = '{lpn}'" for lpn in lpns]
    query = " OR ".join(query_parts)
    
    # Add status requirement with lowercase 'and' as shown in example
    query = f"({query}) and Status = '{required_status}'"
    
    payload = {
        "Query": query,
        "Size": 1000,  # Large size to get all matching LPNs
        "Page": 0
    }
    
    valid_lpns = []
    invalid_lpns = []
    errors = []
    response_data = None
    lpn_data_map = {}  # Initialize here so it's available in error returns
    
    try:
        r = requests.post(url, json=payload, headers=headers, timeout=60, verify=False)
        
        # Get response data
        if r.headers.get('content-type', '').startswith('application/json'):
            try:
                response_data = r.json()
            except:
                response_data = {"raw_text": r.text[:500]}
        else:
            response_data = {"raw_text": r.text[:500]}
        
        if r.status_code != 200:
            # If API call fails, mark all as invalid
            invalid_lpns = lpns
            errors.append(f"API validation failed with status {r.status_code}: {r.text[:200]}")
            return {
                'valid': valid_lpns, 
                'invalid': invalid_lpns, 
                'errors': errors,
                'request_payload': payload,
                'response': response_data,
                'lpn_data': lpn_data_map
            }
        
        # Extract found LPNs from response and store their data (including TotalQuantity)
        # Since we filter by Status in the query, any returned LPNs already have the correct status
        found_lpns = set()
        lpn_data_map = {}  # Map LPN to its full data from API
        if isinstance(response_data, dict):
            # Check both 'Data' and 'data' (API may use either)
            data_list = response_data.get('data') or response_data.get('Data', [])
            if isinstance(data_list, list):
                for item in data_list:
                    if isinstance(item, dict):
                        # Extract IlpnId (case-insensitive check)
                        lpn_id = item.get('IlpnId') or item.get('IlpnID') or item.get('ilpnId') or item.get('LpnId') or item.get('LPN') or item.get('Id')
                        if lpn_id:
                            lpn_id_str = str(lpn_id)
                            found_lpns.add(lpn_id_str)
                            # Store the full item data for this LPN (includes TotalQuantity)
                            lpn_data_map[lpn_id_str] = item
        
        # Categorize LPNs - any LPN returned from the query is valid (already filtered by Status)
        for lpn in lpns:
            if lpn in found_lpns:
                valid_lpns.append(lpn)
            else:
                invalid_lpns.append(lpn)
        
        # If no LPNs found but we searched for some, they're all invalid
        if not found_lpns and lpns:
            invalid_lpns = lpns
            errors.append(f"No LPNs found with Status = '{required_status}'")
        
    except Exception as e:
        # On exception, mark all as invalid
        invalid_lpns = lpns
        errors.append(f"Validation error: {str(e)}")
        response_data = {"error": str(e)}
        lpn_data_map = {}
    
    return {
        'valid': valid_lpns, 
        'invalid': invalid_lpns, 
        'errors': errors,
        'request_payload': payload,
        'response': response_data,
        'lpn_data': lpn_data_map
    }

def validate_locations(org, token, locations, log_callback=None):
    """
    Validate that locations exist and have LocationTypeId = 'STORAGE'.
    Returns: {
        'valid': [list of valid locations],
        'invalid': [list of invalid locations],
        'errors': [list of error messages],
        'request_payload': payload sent,
        'response': response received
    }
    """
    if not locations:
        return {'valid': [], 'invalid': [], 'errors': [], 'request_payload': None, 'response': None}
    
    url = f"https://{API_HOST}{LOCATION_SEARCH_PATH}"
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
        "selectedOrganization": org.upper(),
        "selectedLocation": f"{org.upper()}-DM1"
    }
    
    # Build query: LocationId in ('LOC1','LOC2','LOC3') and LocationTypeId = 'STORAGE'
    location_list = "','".join(locations)
    query = f"LocationId in ('{location_list}') and LocationTypeId = 'STORAGE'"
    
    payload = {
        "Query": query,
        "Size": 1000  # Large size to get all matching locations
    }
    
    valid_locations = []
    invalid_locations = []
    errors = []
    response_data = None
    
    try:
        r = requests.post(url, json=payload, headers=headers, timeout=60, verify=False)
        
        # Get response data
        if r.headers.get('content-type', '').startswith('application/json'):
            try:
                response_data = r.json()
            except:
                response_data = {"raw_text": r.text[:500]}
        else:
            response_data = {"raw_text": r.text[:500]}
        
        if r.status_code != 200:
            # If API call fails, mark all as invalid
            invalid_locations = locations
            errors.append(f"API validation failed with status {r.status_code}: {r.text[:200]}")
            return {
                'valid': valid_locations, 
                'invalid': invalid_locations, 
                'errors': errors,
                'request_payload': payload,
                'response': response_data
            }
        
        # Extract found locations from response
        # Since we filter by LocationTypeId in the query, any returned locations already have the correct type
        found_locations = set()
        if isinstance(response_data, dict):
            # Check both 'Data' and 'data' (API may use either)
            data_list = response_data.get('data') or response_data.get('Data', [])
            if isinstance(data_list, list):
                for item in data_list:
                    if isinstance(item, dict):
                        # Extract LocationId (case-insensitive check)
                        loc_id = item.get('LocationId') or item.get('LocationID') or item.get('locationId') or item.get('LOCATION') or item.get('Id')
                        if loc_id:
                            found_locations.add(str(loc_id))
        
        # Categorize locations - any location returned from the query is valid (already filtered by LocationTypeId)
        for loc in locations:
            if loc in found_locations:
                valid_locations.append(loc)
            else:
                invalid_locations.append(loc)
        
        # If no locations found but we searched for some, they're all invalid
        if not found_locations and locations:
            invalid_locations = locations
            errors.append("No locations found with LocationTypeId = 'STORAGE'")
        
    except Exception as e:
        # On exception, mark all as invalid
        invalid_locations = locations
        errors.append(f"Validation error: {str(e)}")
        response_data = {"error": str(e)}
    
    return {
        'valid': valid_locations, 
        'invalid': invalid_locations, 
        'errors': errors,
        'request_payload': payload,
        'response': response_data
    }

def validate_olpns(org, token, olpns, required_statuses=['7200', '7400', '7600'], log_callback=None):
    """
    Validate that OLPNs exist and have Status in ('7200', '7400', '7600').
    Returns: {
        'valid': [list of valid OLPNs],
        'invalid': [list of invalid OLPNs],
        'errors': [list of error messages],
        'request_payload': payload sent,
        'response': response received
    }
    """
    if not olpns:
        return {'valid': [], 'invalid': [], 'errors': [], 'request_payload': None, 'response': None}
    
    url = f"https://{API_HOST}{OLPN_SEARCH_PATH}"
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
        "selectedOrganization": org.upper(),
        "selectedLocation": f"{org.upper()}-DM1"
    }
    
    # Build query: OlpnId in ('OLPN1','OLPN2','OLPN3') and Status in ('7200', '7400', '7600')
    olpn_list = "','".join(olpns)
    status_list = "','".join(required_statuses)
    query = f"OlpnId in ('{olpn_list}') and Status in ('{status_list}')"
    
    payload = {
        "Query": query,
        "Size": 1000  # Large size to get all matching OLPNs
    }
    
    valid_olpns = []
    invalid_olpns = []
    errors = []
    response_data = None
    
    try:
        r = requests.post(url, json=payload, headers=headers, timeout=60, verify=False)
        
        # Get response data
        if r.headers.get('content-type', '').startswith('application/json'):
            try:
                response_data = r.json()
            except:
                response_data = {"raw_text": r.text[:500]}
        else:
            response_data = {"raw_text": r.text[:500]}
        
        if r.status_code != 200:
            # If API call fails, mark all as invalid
            invalid_olpns = olpns
            errors.append(f"API validation failed with status {r.status_code}: {r.text[:200]}")
            return {
                'valid': valid_olpns, 
                'invalid': invalid_olpns, 
                'errors': errors,
                'request_payload': payload,
                'response': response_data
            }
        
        # Extract found OLPNs and their shipments from response
        # Since we filter by Status in the query, any returned OLPNs already have the correct status
        found_olpns = set()
        olpn_shipment_map = {}  # Map OLPN -> Shipment
        if isinstance(response_data, dict):
            # Check both 'Data' and 'data' (API may use either)
            data_list = response_data.get('data') or response_data.get('Data', [])
            if isinstance(data_list, list):
                for item in data_list:
                    if isinstance(item, dict):
                        # Extract OlpnId (case-insensitive check)
                        olpn_id = item.get('OlpnId') or item.get('OlpnID') or item.get('olpnId') or item.get('OLPN') or item.get('Id')
                        if olpn_id:
                            olpn_id = str(olpn_id)
                            found_olpns.add(olpn_id)
                            # Extract ShipmentId (case-insensitive check)
                            shipment_id = item.get('ShipmentId') or item.get('ShipmentID') or item.get('shipmentId') or item.get('SHIPMENT') or item.get('Shipment')
                            if shipment_id:
                                olpn_shipment_map[olpn_id] = str(shipment_id)
        
        # Categorize OLPNs - any OLPN returned from the query is valid (already filtered by Status)
        for olpn in olpns:
            if olpn in found_olpns:
                valid_olpns.append(olpn)
            else:
                invalid_olpns.append(olpn)
        
        # If no OLPNs found but we searched for some, they're all invalid
        if not found_olpns and olpns:
            invalid_olpns = olpns
            errors.append(f"No OLPNs found with Status in {required_statuses}")
        
    except Exception as e:
        # On exception, mark all as invalid
        invalid_olpns = olpns
        errors.append(f"Validation error: {str(e)}")
        response_data = {"error": str(e)}
    
    return {
        'valid': valid_olpns, 
        'invalid': invalid_olpns, 
        'errors': errors,
        'request_payload': payload,
        'response': response_data,
        'olpn_shipment_map': olpn_shipment_map  # Map of OLPN -> Shipment from API response
    }

def generate_receiving_message(lpns):
    """
    Generate RECEIVE message format for multiple LPNs.
    Format: RECEIVE^LPN^MHE-Receiving^
    From Postman: "RECEIVE^LPN01330^MHE-Receiving^"
    """
    if not lpns:
        return None
    
    # Generate one message string per LPN
    message_strings = [f"RECEIVE^{lpn}^MHE-Receiving^" for lpn in lpns]
    
    return {
        "EndpointId": MHE_ENDPOINT_ID,
        "Message": message_strings
    }

def generate_putaway_message(lpn_location_pairs, user=None, org=None, lpn_data_map=None):
    """
    Generate IBPUTAWAY message format for multiple LPN,Location pairs (complex pipe-delimited)
    New format: "IBPUTAWAY^LPN^^^TotalQuantity^Location^Divert^^base64data^^^^^"
    Args:
        lpn_location_pairs: List of dicts with 'lpn' and 'location' keys
        lpn_data_map: Optional dict mapping LPN to its API data (for TotalQuantity)
    """
    if not lpn_location_pairs:
        return None
    import base64
    
    # Build base64 encoded data: user_base64_org_org-DM1
    # Format: base64(user)_org_org-DM1
    org_upper = (org or '').upper()
    user_str = user or f'sdtadmin@{org_upper.lower()}' if org else 'sdtadmin@'
    user_b64 = base64.b64encode(user_str.encode()).decode()
    base64_data = f"{user_b64}_{org_upper}_{org_upper}-DM1"
    
    # Generate one message string per LPN,Location pair
    # Format: IBPUTAWAY^LPN^^^TotalQuantity^Location^Divert^^base64data^^^^^
    message_strings = []
    for pair in lpn_location_pairs:
        lpn = pair.get('lpn', '')
        location = pair.get('location', '')
        
        # Get TotalQuantity from lpn_data_map if available
        total_quantity = '0'
        if lpn_data_map and lpn in lpn_data_map:
            lpn_data = lpn_data_map[lpn]
            # Try different case variations for TotalQuantity
            total_quantity = str(lpn_data.get('TotalQuantity') or 
                                lpn_data.get('totalQuantity') or 
                                lpn_data.get('Totalquantity') or 
                                lpn_data.get('TOTALQUANTITY') or '0')
        
        # New format: IBPUTAWAY^LPN^^^TotalQuantity^Location^Divert^^base64data^^^^^
        message_str = f"IBPUTAWAY^{lpn}^^^{total_quantity}^{location}^Divert^^{base64_data}^^^^^"
        message_strings.append(message_str)
    return {
        "EndpointId": MHE_ENDPOINT_ID,
        "Message": message_strings
    }

def generate_picking_message(input_data):
    """
    Generate PICKING message format (very complex pipe-delimited)
    From Postman: "PICKING^DG98700028^1^PICK1909^^0000099999100011136^^^^OLPN^4000041^^^^^^^^^^3^^^^^^^^^^"
    This is a placeholder - actual format depends on specific requirements
    """
    if not input_data:
        return None
    # Simplified format - will need to be customized based on actual requirements
    # Format appears to be: PICKING^[order]^[qty]^[task]^[empty]^[olpn]^[empty]^[empty]^[empty]^[container type]^[item]^[many empty fields]^[qty]^[many empty fields]^
    message_str = f"PICKING^{input_data}^1^PICK1909^^0000099999100011136^^^^OLPN^4000041^^^^^^^^^^3^^^^^^^^^^"
    return {
        "EndpointId": MHE_ENDPOINT_ID,
        "Message": [message_str]
    }

def generate_loading_message(lpn_shipment_pairs, org=None):
    """
    Generate Olpn_Loaded message format for multiple LPN,Shipment pairs (complex with base64 encoded data)
    From Postman: "Olpn_Loaded^^^^0000099999100002431^SHI000001118^^ZGVtb3dlYkBzcy1kZW1v_U1MtREVNTw==_U1MtREVNTy1ETTE="
    Args:
        lpn_shipment_pairs: List of dicts with 'lpn' and 'shipment' keys
    """
    if not lpn_shipment_pairs:
        return None
    # Generate one message string per LPN,Shipment pair
    # Format: Olpn_Loaded^[empty]^[empty]^[empty]^[olpn]^[shipment]^[empty]^[base64 encoded org/facility data]^
    message_strings = []
    for pair in lpn_shipment_pairs:
        olpn = pair.get('lpn', '')
        shipment = pair.get('shipment', '')
        message_str = f"Olpn_Loaded^^^^{olpn}^{shipment}^^ZGVtb3dlYkBzcy1kZW1v_U1MtREVNTw==_U1MtREVNTy1ETTE="
        message_strings.append(message_str)
    return {
        "EndpointId": MHE_ENDPOINT_ID,
        "Message": message_strings
    }

def send_mhe_message(org, token, message_payload):
    """Send MHE message to Manhattan API"""
    url = f"https://{API_HOST}{MHE_API_PATH}"
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
        "selectedOrganization": org.upper(),
        "selectedLocation": f"{org.upper()}-DM1"
    }
    try:
        r = requests.post(url, json=message_payload, headers=headers, timeout=60, verify=False)
        return {
            "success": r.status_code in [200, 201],
            "status_code": r.status_code,
            "response": r.json() if r.headers.get('content-type', '').startswith('application/json') else r.text,
            "sent_payload": message_payload
        }
    except Exception as e:
        return {
            "success": False,
            "error": str(e),
            "sent_payload": message_payload
        }

# === API ROUTES ===

@app.route('/api/validate_receiving_lpns', methods=['POST'])
def validate_receiving_lpns():
    """Validate LPNs for Receiving section"""
    data = request.json
    input_text = data.get('input', '').strip()
    org = data.get('org', '').strip()
    token = data.get('token', '').strip()
    
    if not input_text:
        return jsonify({"success": False, "error": "Input required"})
    if not org or not token:
        return jsonify({"success": False, "error": "ORG and token required for validation"})
    
    # Parse LPNs from input
    lpns = parse_lpns(input_text)
    if not lpns:
        return jsonify({"success": False, "error": "No valid LPNs found in input"})
    
    # Validate LPNs
    validation_result = validate_lpns(org, token, lpns, required_status='1000')
    
    if validation_result['invalid']:
        error_msg = f"Invalid LPNs (not found or wrong status): {', '.join(validation_result['invalid'])}"
        if validation_result['errors']:
            error_msg += f". Errors: {'; '.join(validation_result['errors'])}"
        return jsonify({
            "success": False,
            "error": error_msg,
            "valid": validation_result['valid'],
            "invalid": validation_result['invalid'],
            "errors": validation_result['errors']
        })
    
    return jsonify({
        "success": True,
        "valid": validation_result['valid'],
        "invalid": validation_result['invalid']
    })

@app.route('/api/generate_receiving', methods=['POST'])
def generate_receiving():
    """Generate MHE message for Receiving section"""
    data = request.json
    input_text = data.get('input', '').strip()
    org = data.get('org', '').strip()
    token = data.get('token', '').strip()
    skip_validation = data.get('skip_validation', False)  # Allow skipping validation if already done
    
    if not input_text:
        return jsonify({"success": False, "error": "Input required"})
    
    # Parse LPNs from input
    lpns = parse_lpns(input_text)
    if not lpns:
        return jsonify({"success": False, "error": "No valid LPNs found in input"})
    
    validation_result = None
    
    # Validate LPNs unless validation is skipped
    if not skip_validation and org and token:
        validation_result = validate_lpns(org, token, lpns, required_status='1000')
        if validation_result['invalid']:
            error_msg = f"Invalid LPNs (not found or wrong status): {', '.join(validation_result['invalid'])}"
            if validation_result['errors']:
                error_msg += f". Errors: {'; '.join(validation_result['errors'])}"
            return jsonify({
                "success": False,
                "error": error_msg,
                "valid": validation_result['valid'],
                "invalid": validation_result['invalid'],
                "errors": validation_result['errors'],
                "validation_request": validation_result.get('request_payload'),
                "validation_response": validation_result.get('response')
            })
        # Use only valid LPNs
        lpns = validation_result['valid']
        if not lpns:
            return jsonify({
                "success": False, 
                "error": "No valid LPNs to generate message for",
                "validation_request": validation_result.get('request_payload'),
                "validation_response": validation_result.get('response')
            })
    
    message = generate_receiving_message(lpns)
    if not message:
        return jsonify({"success": False, "error": "Failed to generate message"})
    
    result = {
        "success": True, 
        "message": message, 
        "lpns_used": lpns
    }
    
    # Include validation details if validation was performed
    if validation_result:
        result["validation_request"] = validation_result.get('request_payload')
        result["validation_response"] = validation_result.get('response')
    
    return jsonify(result)

@app.route('/api/send_receiving', methods=['POST'])
def send_receiving():
    """Send MHE message for Receiving section"""
    data = request.json
    org = data.get('org', '').strip()
    token = data.get('token', '').strip()
    message = data.get('message')
    
    if not org or not token or not message:
        return jsonify({"success": False, "error": "Missing required fields"})
    
    result = send_mhe_message(org, token, message)
    return jsonify(result)

@app.route('/api/generate_putaway', methods=['POST'])
def generate_putaway():
    """Generate MHE message for Putaway section"""
    data = request.json
    input_text = data.get('input', '').strip()
    org = data.get('org', '').strip()
    token = data.get('token', '').strip()
    skip_validation = data.get('skip_validation', False)
    
    if not input_text:
        return jsonify({"success": False, "error": "Input required"})
    
    # Parse LPN,Location pairs from input (format: "LPN1,Location1; LPN2,Location2")
    pairs = parse_lpn_location_pairs(input_text)
    if not pairs:
        return jsonify({"success": False, "error": "No valid LPN,Location pairs found. Use format: 'LPN1,Location1; LPN2,Location2'"})
    
    # Validate that each pair has both LPN and Location
    invalid_pairs = []
    for i, pair in enumerate(pairs):
        if not pair.get('lpn'):
            invalid_pairs.append(f"Pair {i+1}: Missing LPN")
        if not pair.get('location'):
            invalid_pairs.append(f"Pair {i+1}: Missing Location")
    
    if invalid_pairs:
        return jsonify({
            "success": False,
            "error": f"Invalid pairs: {'; '.join(invalid_pairs)}. Use format: 'LPN,Location; LPN,Location'"
        })
    
    # Extract LPNs and locations for validation
    lpns = [pair['lpn'] for pair in pairs]
    locations = [pair['location'] for pair in pairs]
    
    lpn_validation_result = None
    location_validation_result = None
    
    # Validate LPNs and Locations unless validation is skipped
    if not skip_validation and org and token:
        # Validate LPNs (Status = '3000' for Putaway)
        lpn_validation_result = validate_lpns(org, token, lpns, required_status='3000')
        if lpn_validation_result['invalid']:
            error_msg = f"Invalid LPNs (not found or wrong status): {', '.join(lpn_validation_result['invalid'])}"
            if lpn_validation_result['errors']:
                error_msg += f". Errors: {'; '.join(lpn_validation_result['errors'])}"
            return jsonify({
                "success": False,
                "error": error_msg,
                "valid_lpns": lpn_validation_result['valid'],
                "invalid_lpns": lpn_validation_result['invalid'],
                "lpn_errors": lpn_validation_result['errors'],
                "lpn_validation_request": lpn_validation_result.get('request_payload'),
                "lpn_validation_response": lpn_validation_result.get('response')
            })
        
        # Validate Locations (LocationTypeId = 'STORAGE')
        location_validation_result = validate_locations(org, token, locations)
        if location_validation_result['invalid']:
            error_msg = f"Invalid Locations (not found or wrong type): {', '.join(location_validation_result['invalid'])}"
            if location_validation_result['errors']:
                error_msg += f". Errors: {'; '.join(location_validation_result['errors'])}"
            return jsonify({
                "success": False,
                "error": error_msg,
                "valid_locations": location_validation_result['valid'],
                "invalid_locations": location_validation_result['invalid'],
                "location_errors": location_validation_result['errors'],
                "location_validation_request": location_validation_result.get('request_payload'),
                "location_validation_response": location_validation_result.get('response')
            })
        
        # Filter pairs to only include valid LPNs and locations
        valid_lpns_set = set(lpn_validation_result['valid'])
        valid_locations_set = set(location_validation_result['valid'])
        pairs = [pair for pair in pairs if pair['lpn'] in valid_lpns_set and pair['location'] in valid_locations_set]
        if not pairs:
            return jsonify({
                "success": False, 
                "error": "No valid LPN,Location pairs to generate message for",
                "lpn_validation_request": lpn_validation_result.get('request_payload'),
                "lpn_validation_response": lpn_validation_result.get('response'),
                "location_validation_request": location_validation_result.get('request_payload'),
                "location_validation_response": location_validation_result.get('response')
            })
    
    # Get lpn_data_map from validation result to extract TotalQuantity
    lpn_data_map = lpn_validation_result.get('lpn_data', {}) if lpn_validation_result else {}
    
    message = generate_putaway_message(pairs, org=org, lpn_data_map=lpn_data_map)
    if not message:
        return jsonify({"success": False, "error": "Failed to generate message"})
    
    result = {
        "success": True, 
        "message": message, 
        "pairs_used": pairs  # Return pairs instead of just LPNs
    }
    
    # Include validation details if validation was performed
    if lpn_validation_result:
        result["lpn_validation_request"] = lpn_validation_result.get('request_payload')
        result["lpn_validation_response"] = lpn_validation_result.get('response')
    if location_validation_result:
        result["location_validation_request"] = location_validation_result.get('request_payload')
        result["location_validation_response"] = location_validation_result.get('response')
    
    return jsonify(result)

@app.route('/api/send_putaway', methods=['POST'])
def send_putaway():
    """Send MHE message for Putaway section"""
    data = request.json
    org = data.get('org', '').strip()
    token = data.get('token', '').strip()
    message = data.get('message')
    
    if not org or not token or not message:
        return jsonify({"success": False, "error": "Missing required fields"})
    
    result = send_mhe_message(org, token, message)
    return jsonify(result)

@app.route('/api/generate_picking', methods=['POST'])
def generate_picking():
    """Generate MHE message for Picking section"""
    data = request.json
    input_data = data.get('input', '').strip()
    
    if not input_data:
        return jsonify({"success": False, "error": "Input required"})
    
    message = generate_picking_message(input_data)
    if not message:
        return jsonify({"success": False, "error": "Failed to generate message"})
    
    return jsonify({"success": True, "message": message})

@app.route('/api/send_picking', methods=['POST'])
def send_picking():
    """Send MHE message for Picking section"""
    data = request.json
    org = data.get('org', '').strip()
    token = data.get('token', '').strip()
    message = data.get('message')
    
    if not org or not token or not message:
        return jsonify({"success": False, "error": "Missing required fields"})
    
    result = send_mhe_message(org, token, message)
    return jsonify(result)

@app.route('/api/generate_loading', methods=['POST'])
def generate_loading():
    """Generate MHE message for Loading section"""
    data = request.json
    input_text = data.get('input', '').strip()
    org = data.get('org', '').strip()
    token = data.get('token', '').strip()
    skip_validation = data.get('skip_validation', False)
    
    if not input_text:
        return jsonify({"success": False, "error": "Input required"})
    
    # Parse OLPNs from input (format: "OLPN1 OLPN2" or "OLPN1,OLPN2" or "OLPN1;OLPN2")
    olpns = parse_lpns(input_text)
    if not olpns:
        return jsonify({"success": False, "error": "No valid OLPNs found in input"})
    
    olpn_validation_result = None
    
    # Validate OLPNs unless validation is skipped (Status in ('7200', '7400', '7600') for Loading)
    if not skip_validation and org and token:
        olpn_validation_result = validate_olpns(org, token, olpns, required_statuses=['7200', '7400', '7600'])
        if olpn_validation_result['invalid']:
            error_msg = f"Invalid OLPNs (not found or wrong status): {', '.join(olpn_validation_result['invalid'])}"
            if olpn_validation_result['errors']:
                error_msg += f". Errors: {'; '.join(olpn_validation_result['errors'])}"
            return jsonify({
                "success": False,
                "error": error_msg,
                "valid_olpns": olpn_validation_result['valid'],
                "invalid_olpns": olpn_validation_result['invalid'],
                "olpn_errors": olpn_validation_result['errors'],
                "olpn_validation_request": olpn_validation_result.get('request_payload'),
                "olpn_validation_response": olpn_validation_result.get('response')
            })
        
        # Use only valid OLPNs
        olpns = olpn_validation_result['valid']
        if not olpns:
            return jsonify({
                "success": False, 
                "error": "No valid OLPNs to generate message for",
                "olpn_validation_request": olpn_validation_result.get('request_payload'),
                "olpn_validation_response": olpn_validation_result.get('response')
            })
        
        # Extract shipments from validation response
        olpn_shipment_map = olpn_validation_result.get('olpn_shipment_map', {})
        
        # Build LPN,Shipment pairs and check for missing shipments
        pairs = []
        missing_shipments = []
        for olpn in olpns:
            shipment = olpn_shipment_map.get(olpn)
            if not shipment:
                missing_shipments.append(olpn)
            else:
                pairs.append({'lpn': olpn, 'shipment': shipment})
        
        if missing_shipments:
            return jsonify({
                "success": False,
                "error": f"OLPNs missing shipment information: {', '.join(missing_shipments)}",
                "valid_olpns": olpn_validation_result['valid'],
                "invalid_olpns": olpn_validation_result['invalid'],
                "missing_shipments": missing_shipments,
                "olpn_validation_request": olpn_validation_result.get('request_payload'),
                "olpn_validation_response": olpn_validation_result.get('response')
            })
        
        if not pairs:
            return jsonify({
                "success": False,
                "error": "No OLPNs with shipment information to generate message for",
                "olpn_validation_request": olpn_validation_result.get('request_payload'),
                "olpn_validation_response": olpn_validation_result.get('response')
            })
    else:
        # If validation is skipped, we can't extract shipments, so return error
        return jsonify({
            "success": False,
            "error": "Validation required to extract shipment information from OLPNs"
        })
    
    message = generate_loading_message(pairs, org=org)
    if not message:
        return jsonify({"success": False, "error": "Failed to generate message"})
    
    result = {
        "success": True, 
        "message": message, 
        "pairs_used": pairs  # Return pairs with shipment extracted from API
    }
    
    # Include validation details if validation was performed
    if olpn_validation_result:
        result["olpn_validation_request"] = olpn_validation_result.get('request_payload')
        result["olpn_validation_response"] = olpn_validation_result.get('response')
    
    return jsonify(result)

@app.route('/api/send_loading', methods=['POST'])
def send_loading():
    """Send MHE message for Loading section"""
    data = request.json
    org = data.get('org', '').strip()
    token = data.get('token', '').strip()
    message = data.get('message')
    
    if not org or not token or not message:
        return jsonify({"success": False, "error": "Missing required fields"})
    
    result = send_mhe_message(org, token, message)
    return jsonify(result)

@app.route('/api/endpoint_status', methods=['POST'])
def endpoint_status():
    """Check endpoint status using Device Integration API"""
    data = request.json
    org = data.get('org', '').strip()
    token = data.get('token', '').strip()
    endpoint_id = data.get('endpoint_id', MHE_ENDPOINT_ID).strip()
    
    if not org or not token:
        print(f"[ENDPOINT_STATUS] Error: ORG and token required. ORG: {org}, Token present: {bool(token)}")
        return jsonify({"success": False, "error": "ORG and token required"})
    
    url = f"https://{API_HOST}{ENDPOINT_STATUS_PATH}?endpointId={endpoint_id}"
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
        "selectedOrganization": org.upper(),
        "selectedLocation": f"{org.upper()}-DM1"
    }
    
    print(f"[ENDPOINT_STATUS] Checking endpoint status for: {endpoint_id}")
    print(f"[ENDPOINT_STATUS] URL: {url}")
    print(f"[ENDPOINT_STATUS] Headers: selectedOrganization={org.upper()}, selectedLocation={org.upper()}-DM1")
    
    try:
        r = requests.get(url, headers=headers, timeout=10, verify=False)
        
        print(f"[ENDPOINT_STATUS] Response Status Code: {r.status_code}")
        print(f"[ENDPOINT_STATUS] Response Headers Content-Type: {r.headers.get('content-type', 'N/A')}")
        
        if r.status_code == 200:
            response_data = r.json() if r.headers.get('content-type', '').startswith('application/json') else r.text
            
            print(f"[ENDPOINT_STATUS] Response Data Type: {type(response_data)}")
            if isinstance(response_data, dict):
                print(f"[ENDPOINT_STATUS] Response Data Keys: {list(response_data.keys())}")
                print(f"[ENDPOINT_STATUS] Full Response: {json.dumps(response_data, indent=2)}")
            else:
                print(f"[ENDPOINT_STATUS] Response Text (first 500 chars): {str(response_data)[:500]}")
            
            # Extract status from response
            # The API returns status like "Started" or "Stopped"
            # Check various possible field names and nested paths
            status_value = None
            if isinstance(response_data, dict):
                # Check top-level first
                status_value = (
                    response_data.get('Status') or 
                    response_data.get('status') or 
                    response_data.get('state') or
                    response_data.get('State')
                )
                
                # If not found, check nested in 'data' object
                if not status_value and 'data' in response_data:
                    data_obj = response_data.get('data')
                    if isinstance(data_obj, dict):
                        status_value = (
                            data_obj.get('Status') or 
                            data_obj.get('status') or 
                            data_obj.get('state') or
                            data_obj.get('State')
                        )
                
                print(f"[ENDPOINT_STATUS] Extracted Status Value: {status_value}")
            elif isinstance(response_data, str):
                # If response is a string, check if it contains status keywords
                print(f"[ENDPOINT_STATUS] Response is string, searching for status keywords...")
                if 'Started' in response_data or 'started' in response_data:
                    status_value = 'Started'
                elif 'Stopped' in response_data or 'stopped' in response_data:
                    status_value = 'Stopped'
                print(f"[ENDPOINT_STATUS] Extracted Status Value from string: {status_value}")
            
            # Map to online/offline
            is_online = False
            if status_value:
                status_lower = str(status_value).lower()
                is_online = 'started' in status_lower or 'running' in status_lower or 'active' in status_lower
                print(f"[ENDPOINT_STATUS] Status '{status_value}' mapped to online={is_online}")
            else:
                print(f"[ENDPOINT_STATUS] WARNING: No status value found in response!")
            
            result = {
                "success": True,
                "status": status_value or "Unknown",  # Return actual status: 'Started' or 'Stopped'
                "response": response_data
            }
            print(f"[ENDPOINT_STATUS] Returning result: success={result['success']}, status={result['status']}")
            return jsonify(result)
        else:
            # If API call fails, assume offline
            error_text = r.text[:500] if r.text else None
            print(f"[ENDPOINT_STATUS] API call failed with status {r.status_code}")
            print(f"[ENDPOINT_STATUS] Error Response: {error_text}")
            
            result = {
                "success": False,
                "status": "Offline",  # Connection failure - use 'Offline'
                "error": f"API returned status {r.status_code}",
                "response": error_text
            }
            print(f"[ENDPOINT_STATUS] Returning error result: {result}")
            return jsonify(result)
    except Exception as e:
        # On exception, assume offline
        import traceback
        error_trace = traceback.format_exc()
        print(f"[ENDPOINT_STATUS] Exception occurred: {str(e)}")
        print(f"[ENDPOINT_STATUS] Traceback: {error_trace}")
        
        result = {
            "success": False,
            "status": "Offline",  # Exception means connection failure - use 'Offline'
            "error": str(e)
        }
        print(f"[ENDPOINT_STATUS] Returning exception result: {result}")
        return jsonify(result)

@app.route('/api/endpoint_start', methods=['POST'])
def endpoint_start():
    """Start endpoint using Device Integration API"""
    data = request.json
    org = data.get('org', '').strip()
    token = data.get('token', '').strip()
    endpoint_id = data.get('endpoint_id', MHE_ENDPOINT_ID).strip()
    
    if not org or not token:
        print(f"[ENDPOINT_START] Error: ORG and token required. ORG: {org}, Token present: {bool(token)}")
        return jsonify({"success": False, "error": "ORG and token required"})
    
    url = f"https://{API_HOST}{ENDPOINT_START_PATH}?endpointId={endpoint_id}"
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
        "selectedOrganization": org.upper(),
        "selectedLocation": f"{org.upper()}-DM1"
    }
    
    print(f"[ENDPOINT_START] Starting endpoint: {endpoint_id}")
    print(f"[ENDPOINT_START] URL: {url}")
    
    try:
        r = requests.get(url, headers=headers, timeout=10, verify=False)
        
        print(f"[ENDPOINT_START] Response Status Code: {r.status_code}")
        
        if r.status_code == 200:
            response_data = r.json() if r.headers.get('content-type', '').startswith('application/json') else r.text
            print(f"[ENDPOINT_START] Success: {response_data}")
            return jsonify({
                "success": True,
                "message": "Endpoint started successfully",
                "response": response_data
            })
        else:
            error_text = r.text[:500] if r.text else None
            print(f"[ENDPOINT_START] Failed with status {r.status_code}: {error_text}")
            return jsonify({
                "success": False,
                "error": f"API returned status {r.status_code}",
                "response": error_text
            })
    except Exception as e:
        import traceback
        error_trace = traceback.format_exc()
        print(f"[ENDPOINT_START] Exception occurred: {str(e)}")
        print(f"[ENDPOINT_START] Traceback: {error_trace}")
        return jsonify({
            "success": False,
            "error": str(e)
        })

@app.route('/api/endpoint_stop', methods=['POST'])
def endpoint_stop():
    """Stop endpoint using Device Integration API"""
    data = request.json
    org = data.get('org', '').strip()
    token = data.get('token', '').strip()
    endpoint_id = data.get('endpoint_id', MHE_ENDPOINT_ID).strip()
    
    if not org or not token:
        print(f"[ENDPOINT_STOP] Error: ORG and token required. ORG: {org}, Token present: {bool(token)}")
        return jsonify({"success": False, "error": "ORG and token required"})
    
    url = f"https://{API_HOST}{ENDPOINT_STOP_PATH}?endpointId={endpoint_id}"
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
        "selectedOrganization": org.upper(),
        "selectedLocation": f"{org.upper()}-DM1"
    }
    
    print(f"[ENDPOINT_STOP] Stopping endpoint: {endpoint_id}")
    print(f"[ENDPOINT_STOP] URL: {url}")
    
    try:
        r = requests.get(url, headers=headers, timeout=10, verify=False)
        
        print(f"[ENDPOINT_STOP] Response Status Code: {r.status_code}")
        
        if r.status_code == 200:
            response_data = r.json() if r.headers.get('content-type', '').startswith('application/json') else r.text
            print(f"[ENDPOINT_STOP] Success: {response_data}")
            return jsonify({
                "success": True,
                "message": "Endpoint stopped successfully",
                "response": response_data
            })
        else:
            error_text = r.text[:500] if r.text else None
            print(f"[ENDPOINT_STOP] Failed with status {r.status_code}: {error_text}")
            return jsonify({
                "success": False,
                "error": f"API returned status {r.status_code}",
                "response": error_text
            })
    except Exception as e:
        import traceback
        error_trace = traceback.format_exc()
        print(f"[ENDPOINT_STOP] Exception occurred: {str(e)}")
        print(f"[ENDPOINT_STOP] Traceback: {error_trace}")
        return jsonify({
            "success": False,
            "error": str(e)
        })

# === ANALYTICS STATS ENDPOINT ===
@app.route('/api/stats', methods=['GET'])
def get_stats():
    """Get project statistics from Vercel API"""
    VERCEL_API_BASE = "https://api.vercel.com"
    VERCEL_API_TOKEN = os.getenv("VERCEL_API_TOKEN")
    PROJECT_NAME = "MHE_console"
    PROJECT_URL = "https://mhe-console.vercel.app"
    
    if not VERCEL_API_TOKEN:
        return jsonify({
            "project": PROJECT_NAME,
            "url": PROJECT_URL,
            "error": "VERCEL_API_TOKEN environment variable not set",
            "note": "Analytics data (visitors, page views) is only available in Vercel dashboard. This endpoint provides project metadata only.",
            "last_updated": datetime.now().isoformat()
        })
    
    try:
        # Get project ID by listing projects
        projects_url = f"{VERCEL_API_BASE}/v9/projects"
        headers = {
            'Authorization': f'Bearer {VERCEL_API_TOKEN}'
        }
        projects_response = requests.get(projects_url, headers=headers, timeout=10)
        
        if projects_response.status_code != 200:
            return jsonify({
                "project": PROJECT_NAME,
                "url": PROJECT_URL,
                "error": f"Failed to fetch projects: {projects_response.status_code}",
                "note": "Analytics data (visitors, page views) is only available in Vercel dashboard. This endpoint provides project metadata only.",
                "last_updated": datetime.now().isoformat()
            })
        
        projects_data = projects_response.json()
        project = None
        for p in projects_data.get('projects', []):
            if p.get('name', '').lower() == PROJECT_NAME.lower():
                project = p
                break
        
        if not project:
            return jsonify({
                "project": PROJECT_NAME,
                "url": PROJECT_URL,
                "error": f"Project {PROJECT_NAME} not found",
                "note": "Analytics data (visitors, page views) is only available in Vercel dashboard. This endpoint provides project metadata only.",
                "last_updated": datetime.now().isoformat()
            })
        
        # Get latest deployment
        deployments_url = f"{VERCEL_API_BASE}/v6/deployments"
        params = {
            'projectId': project.get('id'),
            'limit': 1,
            'target': 'production',
            'state': 'READY'
        }
        deployments_response = requests.get(deployments_url, headers=headers, params=params, timeout=10)
        
        deployment = None
        if deployments_response.status_code == 200:
            deployments_data = deployments_response.json()
            deployments = deployments_data.get('deployments', [])
            if deployments:
                deployment = deployments[0]
        
        response_data = {
            "project": PROJECT_NAME,
            "url": PROJECT_URL,
            "note": "Analytics data (visitors, page views) is only available in Vercel dashboard. This endpoint provides project metadata only.",
            "project_info": {
                "id": project.get('id'),
                "name": project.get('name')
            },
            "last_updated": datetime.now().isoformat()
        }
        
        if deployment:
            response_data["deployment"] = {
                "id": deployment.get('id'),
                "url": deployment.get('url'),
                "created": deployment.get('createdAt'),
                "state": deployment.get('state')
            }
        
        return jsonify(response_data)
        
    except Exception as e:
        return jsonify({
            "project": PROJECT_NAME,
            "url": PROJECT_URL,
            "error": f"API error: {str(e)}",
            "note": "Analytics data (visitors, page views) is only available in Vercel dashboard. This endpoint provides project metadata only.",
            "last_updated": datetime.now().isoformat()
        })

# === FALLBACK: Serve index.html for SPA ===
@app.route('/', defaults={'path': ''})
@app.route('/<path:path>')
def serve_static(path):
    return send_from_directory(os.path.dirname(os.path.dirname(__file__)), 'index.html')

if __name__ == '__main__':
    app.run(debug=True, port=5000)

