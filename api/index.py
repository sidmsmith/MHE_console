# api/index.py
from flask import Flask, request, jsonify, send_from_directory
import json
import re
import os
import requests
from requests.auth import HTTPBasicAuth
from datetime import datetime
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

app = Flask(__name__)

# === SECURE CONFIG (from Vercel Environment Variables) ===
USAGE_INGEST_URL = os.getenv("MANHATTAN_USAGE_INGEST_URL", "").strip()
USAGE_INGEST_SECRET = os.getenv("MANHATTAN_USAGE_INGEST_SECRET", "").strip()

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
def forward_usage_event(payload):
    """POST usage JSON to Manhattan app usage dashboard ingest (Neon)."""
    if not USAGE_INGEST_URL:
        print("[usage] MANHATTAN_USAGE_INGEST_URL not set; event not recorded")
        return
    headers = {"Content-Type": "application/json"}
    if USAGE_INGEST_SECRET:
        headers["Authorization"] = f"Bearer {USAGE_INGEST_SECRET}"
    try:
        requests.post(USAGE_INGEST_URL, json=payload, headers=headers, timeout=8)
    except Exception as e:
        print(f"[usage] Forward failed: {e}")

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
    # Track app opened event (metadata will be added by frontend)
    return jsonify({"success": True})

@app.route('/api/usage-track', methods=['POST'])
def usage_track():
    """Record usage events via centralized dashboard ingest."""
    try:
        data = request.json
        event_name = data.get('event_name')
        metadata = data.get('metadata', {})
        
        # Build complete payload with app info and timestamp
        payload = {
            **metadata,
            "event_name": event_name,
            "app_name": "mhe-console",
            "app_version": "2.4.3",
            "timestamp": datetime.now().isoformat()
        }
        
        forward_usage_event(payload)
        return jsonify({"success": True})
    except Exception as e:
        # Silently fail - don't interrupt user experience
        print(f"[usage] Failed to track event: {e}")
        return jsonify({"success": True})  # Return success anyway

@app.route('/api/auth', methods=['POST'])
def auth():
    org = request.json.get('org', '').strip()
    if not org:
        return jsonify({"success": False, "error": "ORG required"})
    token = get_manhattan_token(org)
    if token:
        return jsonify({"success": True, "token": token})
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
INVENTORY_SEARCH_PATH = "/dcinventory/api/dcinventory/inventory/search"
TASK_SEARCH_PATH = "/task/api/task/task/search"
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

def lpn_contents(org, token, lpns):
    """{lpn: {'TotalQuantity', 'ItemId'}} from inventory search - the iLPN record itself carries no quantity."""
    if not lpns:
        return {}
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json",
               "selectedOrganization": org.upper(), "selectedLocation": f"{org.upper()}-DM1"}
    query = "IlpnId in ('" + "','".join(lpns) + "')"
    try:
        r = requests.post(f"https://{API_HOST}{INVENTORY_SEARCH_PATH}", json={"Query": query, "Size": 1000},
                          headers=headers, timeout=60, verify=False)
        rows = ((r.json() or {}).get("data") or []) if r.status_code == 200 else []
    except Exception:
        rows = []
    out = {}
    for row in rows:
        lpn = row.get("IlpnId") or row.get("InventoryContainerId")
        if not lpn:
            continue
        cur = out.setdefault(lpn, {"TotalQuantity": 0, "ItemId": row.get("ItemId")})
        cur["TotalQuantity"] += row.get("OnHand") or 0
        if cur["ItemId"] != row.get("ItemId"):
            cur["ItemId"] = ""          # mixed-item LPN: leave the item out of the message
    for v in out.values():
        q = v["TotalQuantity"]
        v["TotalQuantity"] = int(q) if float(q).is_integer() else q
    return out


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

# === CONFIGURED PARSER TEMPLATES (v2.3.0) ===
# WM reads an MHE message with the parser template its subscriber names for (endpoint, message type):
# Device Integration > Subscriber (EndpointId + MessageTypeId.PayloadMessageTypeId -> SourceSubscriber.ParserTemplateId)
# > Parser Template (Delimiter, ParserTemplateSpec[]: FieldSeq + FieldName). Messages are built from that layout,
# so they match whatever the environment has configured; the hard-coded formats are only a fallback.
DEI_HIERARCHY = "/dmui-facade/api/dmui-facade/hierarchy/com-manh-cp-device-integration/"
PARSER_CACHE_SECONDS = 300
_parser_cache = {}


def _dei_search(org, token, view, filters=None, size=500):
    body = {"ViewName": view, "Filters": filters or [], "RequestAttributeIds": [], "SearchOptions": [], "SearchChains": [],
            "FilterExpression": None, "Page": 0, "TotalCount": -1, "SortOrder": "asc", "MultiSort": [], "SortIndicator": "chevron-up",
            "TimeZone": "America/New_York", "IsCommonUI": False, "ComponentShortName": None, "EnableMaxCountLimit": True,
            "MaxCountLimit": 500, "PageQuery": None, "ChildQuery": None, "ComponentName": "com-manh-cp-device-integration",
            "Size": size, "AdvancedFilter": False, "ConfigGroupType": view, "RuleType": None, "QueryFilter": None}
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json",
               "selectedOrganization": org.upper(), "selectedLocation": f"{org.upper()}-DM1"}
    r = requests.post(f"https://{API_HOST}{DEI_HIERARCHY}{view}", json=body, headers=headers, timeout=60, verify=False)
    r.raise_for_status()
    return ((r.json() or {}).get("data") or {}).get("Results") or []


def _ref(value, key):
    """Hierarchy references come back as {'EndpointId': 'X'} or as a plain value."""
    return value.get(key) if isinstance(value, dict) else value


def get_parser_template(org, token, message_type, endpoint_id=None):
    """(template, error): the parser template WM uses for this message type on our endpoint.
    template = {'id', 'delimiter', 'fields': [(seq, name), ...], 'endpoint'} (one line; first field per position)."""
    endpoint_id = endpoint_id or MHE_ENDPOINT_ID
    key = (org.upper(), endpoint_id, message_type)
    hit = _parser_cache.get(key)
    if hit and datetime.now().timestamp() - hit[0] < PARSER_CACHE_SECONDS:
        return hit[1], None
    try:
        subs = _dei_search(org, token, "Subscriber")
        sub = next((s for s in subs if _ref(s.get("EndpointId"), "EndpointId") == endpoint_id
                    and _ref(s.get("MessageTypeId") or s.get("PayloadMessageType"), "PayloadMessageTypeId") == message_type
                    and _ref(s.get("SourceSubscriber") or {}, "ParserTemplateId")), None)
        if not sub:
            return None, f"no subscriber for {message_type} on {endpoint_id}"
        parser_id = _ref(sub["SourceSubscriber"], "ParserTemplateId")
        if isinstance(parser_id, dict):
            parser_id = parser_id.get("ParserTemplateId")
        rows = _dei_search(org, token, "ParserTemplate", [{"ViewName": "ParserTemplate", "AttributeId": "ParserTemplateId", "DataType": "string",
                                                          "requiredFilter": False, "Operator": "=", "FilterValues": [parser_id], "negativeFilter": False}], 25)
        tpl = next((x for x in rows if x.get("ParserTemplateId") == parser_id), None)
        if not tpl:
            return None, f"parser template {parser_id} not found"
        seen, fields = set(), []
        for s in sorted(tpl.get("ParserTemplateSpec") or [], key=lambda s: (s.get("FieldSeq") or 0)):
            seq = s.get("FieldSeq")
            if seq is None or seq in seen:
                continue          # multi-line templates repeat a position per line type: the first line is the message
            seen.add(seq)
            fields.append((seq, s.get("FieldName") or ""))
        if not fields:
            return None, f"parser template {parser_id} has no fields"
        delim = tpl.get("Delimiter") or "^"
        if isinstance(delim, dict):
            delim = next((v for v in delim.values() if isinstance(v, str) and v), "^")
        template = {"id": parser_id, "delimiter": delim, "fields": fields, "endpoint": endpoint_id}
        _parser_cache[key] = (datetime.now().timestamp(), template)
        return template, None
    except Exception as e:  # the hard-coded format is used instead; the console shows why
        return None, f"parser lookup failed: {e}"


def _norm(name):
    return "".join(ch for ch in (name or "").lower() if ch.isalnum())


def build_from_parser(template, message_type, values):
    """One message string laid out by the parser: each field's value from `values` (matched by field name,
    case and punctuation ignored; MessageType is the message type), empty when we have none."""
    vals = {_norm(k): v for k, v in values.items()}
    vals["messagetype"] = message_type
    seqs = [s for s, _ in template["fields"]]
    base = 0 if min(seqs) == 0 else 1          # some templates number fields from 0, most from 1
    parts = [""] * (max(seqs) - base + 1)
    for seq, name in template["fields"]:
        v = vals.get(_norm(name))
        parts[seq - base] = "" if v is None else str(v)
    return template["delimiter"].join(parts)


def parser_info(template, error, message_type, example):
    """What the page's console shows about how the message was built."""
    if template:
        return {"source": "configured", "message_type": message_type, "endpoint": template["endpoint"], "parser": template["id"],
                "fields": [f"{s}:{n}" for s, n in template["fields"]], "example": example}
    return {"source": "built-in", "message_type": message_type, "reason": error, "example": example}


def generate_receiving_message(lpns, template=None, asn_of=None):
    """
    Generate RECEIVE message format for multiple LPNs.
    Format: RECEIVE^^LPN^^^^^^^
    Example: "RECEIVE^^LPN6000005^^^^^^^"
    """
    if not lpns:
        return None
    
    # Generate one message string per LPN
    message_strings = ([build_from_parser(template, "RECEIVE", {"LpnId": lpn, "IlpnId": lpn, "ContainerId": lpn, "AsnId": (asn_of or {}).get(lpn) or ""}) for lpn in lpns]
                       if template else [f"RECEIVE^^{lpn}^^^^^^^" for lpn in lpns])   # configured parser, else built-in
    
    return {
        "EndpointId": MHE_ENDPOINT_ID,
        "Message": message_strings
    }

def generate_putaway_message(lpn_location_pairs, user=None, org=None, lpn_data_map=None, template=None):
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
    
    # Build base64 encoded data in exact expected format:
    # base64(user)_base64(org)_base64(org-DM1)
    org_upper = (org or '').upper()
    user_str = user or (f'sdtadmin@{org_upper.lower()}' if org else 'sdtadmin@')
    user_b64 = base64.b64encode(user_str.encode()).decode()
    org_b64 = base64.b64encode(org_upper.encode()).decode()
    org_dm1_b64 = base64.b64encode(f"{org_upper}-DM1".encode()).decode()
    base64_data = f"{user_b64}_{org_b64}_{org_dm1_b64}"
    
    # Generate one message string per LPN,Location pair
    # Exact format: IBPUTAWAY^LPN^^^TotalQuantity^Location^Divert^^base64data^^^^^^
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
        
        # Exact format: IBPUTAWAY^LPN^^^TotalQuantity^Location^Divert^^base64data^^^^^^
        item_id = ((lpn_data_map or {}).get(lpn) or {}).get("ItemId") or ""
        message_str = (build_from_parser(template, "IBPUTAWAY", {"ContainerId": lpn, "LpnId": lpn, "IlpnId": lpn, "ItemId": item_id, "Quantity": total_quantity,
                                                                 "LocationId": location, "Divert": "Divert", "WMContextId": base64_data})
                       if template else f"IBPUTAWAY^{lpn}^^^{total_quantity}^{location}^Divert^^{base64_data}^^^^^^")
        message_strings.append(message_str)
    return {
        "EndpointId": MHE_ENDPOINT_ID,
        "Message": message_strings
    }

def wm_context(org, user=None):
    """WMContextId for messages that carry one: base64(user)_base64(org)_base64(org-DM1)."""
    import base64
    org_upper = (org or '').upper()
    user_str = user or (f'sdtadmin@{org_upper.lower()}' if org else 'sdtadmin@')
    enc = lambda s: base64.b64encode(s.encode()).decode()
    return f"{enc(user_str)}_{enc(org_upper)}_{enc(org_upper + '-DM1')}"


# === PICKING (v2.4.0) ===
# One PICKING message per task line: WM commits the move (pickpack/pick/commitPickMove, "Pick To oLPN") and, once the
# oLPN's last unit is picked, completes the task and packs the oLPN (7200) by itself. CloseIndicator stays false:
# with it set WM closes the oLPN and ignores that message's quantity (confirmed in SS-DEMO 2026-10-15 - an oLPN closed
# with nothing picked is canceled). Input per entry: "oLPN" = pick every open line, "oLPN,Item,Qty" = pick that much.
OPEN_OLPN_STATUSES = {"1000", "7100"}       # Created / Packing


def _mawm_headers(org, token):
    return {"Authorization": f"Bearer {token}", "Content-Type": "application/json",
            "selectedOrganization": org.upper(), "selectedLocation": f"{org.upper()}-DM1"}


def _search(org, token, path, query, size=200):
    r = requests.post(f"https://{API_HOST}{path}", json={"Query": query, "Size": size, "Page": 0},
                      headers=_mawm_headers(org, token), timeout=60, verify=False)
    if r.status_code != 200:
        raise RuntimeError(f"{path.rsplit('/', 2)[-2]} search failed: {r.status_code} {r.text[:200]}")
    return (r.json() or {}).get("data") or []


def open_pick_lines(org, token, olpn):
    """(lines, error): this oLPN's open pick lines - task, line, order, item, location and the quantity still to pick."""
    olpns = _search(org, token, OLPN_SEARCH_PATH, f"OlpnId = '{olpn}'", 5)
    if not olpns:
        return [], f"oLPN {olpn} not found"
    status = str(olpns[0].get("Status") or "")
    if status not in OPEN_OLPN_STATUSES:
        return [], f"oLPN {olpn} is status {status} - only Created (1000) or Packing (7100) oLPNs can be picked"
    tasks = _search(org, token, TASK_SEARCH_PATH, f"TaskDetail.OlpnId = '{olpn}' and TransactionTypeId = 'Pick' and Status != '8000' and Status != '9000'", 20)
    lines = []
    for task in tasks:
        for d in task.get("TaskDetail") or []:
            if d.get("OlpnId") != olpn or str(d.get("Status") or "") in ("8000", "9000"):
                continue
            if (d.get("SourceContainerTypeId") or "LOCATION") != "LOCATION":
                return [], f"task {task.get('TaskId')} picks from a {d.get('SourceContainerTypeId')} - only location picks are supported"
            left = float(d.get("Quantity") or 0) - float(d.get("CompletedQuantity") or 0)
            if left > 0:
                lines.append({"task": task.get("TaskId"), "line": d.get("TaskDetailId"), "order": d.get("OrderId"), "order_line": d.get("OrderLineId"),
                              "item": d.get("ItemId"), "location": d.get("SourceLocationId"), "left": left})
    if not lines:
        return [], f"oLPN {olpn} has no open pick lines (status {status})"
    return lines, None


def parse_picking_input(text):
    """'oLPN' or 'oLPN,Item,Qty' entries, separated by semicolons or new lines (a line of bare oLPNs may also use spaces)."""
    entries = []
    for part in re.split(r"[;\n]+", text or ""):
        part = part.strip()
        if not part:
            continue
        bits = [b.strip() for b in part.split(",") if b.strip()]
        if len(bits) == 3:
            entries.append({"olpn": bits[0], "item": bits[1], "qty": bits[2]})
        elif len(bits) == 1:
            entries.extend({"olpn": o} for o in bits[0].split())
        else:
            entries.append({"error": f"'{part}': use oLPN or oLPN,Item,Qty"})
    return entries


def plan_picks(org, token, entries):
    """(picks, errors): one pick per task line - everything left for 'oLPN', or the asked quantity spread over the item's lines."""
    picks, errors, cache = [], [], {}
    for e in entries:
        if e.get("error"):
            errors.append(e["error"])
            continue
        olpn = e["olpn"]
        if olpn not in cache:
            cache[olpn] = open_pick_lines(org, token, olpn)
        lines, err = cache[olpn]
        if err:
            errors.append(err)
            continue
        if "item" not in e:
            for l in lines:
                picks.append({**l, "olpn": olpn, "qty": l["left"]})
                l["left"] = 0
            continue
        try:
            want = float(e["qty"])
        except ValueError:
            errors.append(f"{olpn},{e['item']},{e['qty']}: quantity must be a number")
            continue
        mine = [l for l in lines if l["item"] == e["item"] and l["left"] > 0]
        left = sum(l["left"] for l in mine)
        if not mine:
            errors.append(f"oLPN {olpn} has nothing left to pick for item {e['item']}")
        elif want <= 0 or want > left:
            errors.append(f"oLPN {olpn} item {e['item']}: {e['qty']} asked, {left:g} left to pick")
        else:
            for l in mine:
                take = min(want, l["left"])
                if take > 0:
                    picks.append({**l, "olpn": olpn, "qty": take})
                    l["left"] -= take
                    want -= take
    for p in picks:
        p["qty"] = int(p["qty"]) if float(p["qty"]).is_integer() else p["qty"]
        p.pop("left", None)
    return picks, errors


def generate_picking_message(picks, org=None, template=None):
    """One PICKING message per pick (see the PICKING note above)."""
    if not picks:
        return None
    ctx = wm_context(org)
    messages = []
    for p in picks:
        values = {"OrderId": p["order"], "OrderLineId": p["order_line"], "TaskId": p["task"], "TaskDetailId": p["line"], "OlpnId": p["olpn"],
                  "DestinationContainerType": "OLPN", "ItemId": p["item"], "PickedQuantity": p["qty"], "CloseIndicator": "false",
                  "ShortIndicator": "false", "PickLocationId": p["location"], "WMContextId": ctx}
        if template:
            messages.append(build_from_parser(template, "PICKING", values))
        else:   # SS-DEMO's (fixed) MhePickingMessageFormatFromWCS layout
            messages.append(f"PICKING^{p['order']}^{p['order_line']}^{p['task']}^{p['line']}^{p['olpn']}^^^^OLPN^{p['item']}^^^^^^^^^^"
                            f"{p['qty']}^false^false^{p['location']}^^{ctx}^^^^")
    return {"EndpointId": MHE_ENDPOINT_ID, "Message": messages}

def generate_loading_message(lpn_shipment_pairs, org=None, template=None):
    """
    Generate Olpn_Loaded message format for multiple LPN,Shipment pairs.
    Format example: "Olpn_Loaded^^^^0000099999100002448^SHI000001118^"
    Args:
        lpn_shipment_pairs: List of dicts with 'lpn' and 'shipment' keys
    """
    if not lpn_shipment_pairs:
        return None
    # Generate one message string per LPN,Shipment pair
    # Format: Olpn_Loaded^[empty]^[empty]^[empty]^[olpn]^[shipment]^
    message_strings = []
    for pair in lpn_shipment_pairs:
        olpn = pair.get('lpn', '')
        shipment = pair.get('shipment', '')
        message_str = (build_from_parser(template, "Olpn_Loaded", {"OlpnId": olpn, "ShipmentId": shipment})
                       if template else f"Olpn_Loaded^^^^{olpn}^{shipment}^")
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
    
    template, parser_error = get_parser_template(org, token, "RECEIVE") if org and token else (None, "not signed in")
    asn_of = {l: ((validation_result or {}).get('lpn_data') or {}).get(l, {}).get('AsnId') for l in lpns}   # each LPN's ASN, from the validation
    message = generate_receiving_message(lpns, template, asn_of)
    if not message:
        return jsonify({"success": False, "error": "Failed to generate message"})
    
    result = {
        "success": True, 
        "message": message, 
        "lpns_used": lpns,
        "parser": parser_info(template, parser_error, "RECEIVE", message["Message"][0])
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
    if org and token:   # quantity + item from inventory (the iLPN search has no TotalQuantity)
        for lpn, contents in lpn_contents(org, token, [pair['lpn'] for pair in pairs]).items():
            lpn_data_map[lpn] = {**lpn_data_map.get(lpn, {}), **contents}
    
    template, parser_error = get_parser_template(org, token, "IBPUTAWAY") if org and token else (None, "not signed in")
    message = generate_putaway_message(pairs, org=org, lpn_data_map=lpn_data_map, template=template)
    if not message:
        return jsonify({"success": False, "error": "Failed to generate message"})
    
    result = {
        "success": True, 
        "message": message, 
        "pairs_used": pairs,
        "parser": parser_info(template, parser_error, "IBPUTAWAY", message["Message"][0])
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
    """Generate MHE message for Picking section: 'oLPN' picks every open line, 'oLPN,Item,Qty' picks that quantity."""
    data = request.json
    input_text = data.get('input', '').strip()
    org = data.get('org', '').strip()
    token = data.get('token', '').strip()
    if not input_text:
        return jsonify({"success": False, "error": "Input required"})
    if not org or not token:
        return jsonify({"success": False, "error": "Authenticate first - picking looks up the oLPN's pick tasks"})
    entries = parse_picking_input(input_text)
    if not entries:
        return jsonify({"success": False, "error": "Enter an oLPN, or oLPN,Item,Qty (separate entries with semicolons)"})
    try:
        picks, errors = plan_picks(org, token, entries)
    except Exception as e:
        return jsonify({"success": False, "error": f"Pick lookup failed: {e}"})
    if errors:
        return jsonify({"success": False, "error": "; ".join(errors), "picks": picks})
    template, parser_error = get_parser_template(org, token, "PICKING")
    message = generate_picking_message(picks, org=org, template=template)
    return jsonify({"success": True, "message": message, "picks": picks,
                    "parser": parser_info(template, parser_error, "PICKING", message["Message"][0])})


# === ALL ENDPOINTS (v2.4.0) ===
# A message needs its source endpoint (ours) and the WM endpoint its destination subscriber sends to - e.g. PICKING ->
# WMPickingService. A stopped WM endpoint ends the message in the journal as ERROR ("the endpoint is stopped").
CONSOLE_MESSAGE_TYPES = {"RECEIVE": "Receiving", "IBPUTAWAY": "Putaway", "PICKING": "Picking", "Olpn_Loaded": "Loading"}
_endpoint_cache = {}


def expected_endpoints(org, token):
    """[{endpoint, sections}] - our endpoint first, then each WM endpoint the console's message types are sent to."""
    hit = _endpoint_cache.get(org.upper())
    if hit and datetime.now().timestamp() - hit[0] < PARSER_CACHE_SECONDS:
        return hit[1]
    found = {MHE_ENDPOINT_ID: ["All (source)"]}
    for s in _dei_search(org, token, "Subscriber"):
        mtype = _ref(s.get("MessageTypeId") or s.get("PayloadMessageType"), "PayloadMessageTypeId")
        ep = _ref(s.get("EndpointId"), "EndpointId")
        if mtype in CONSOLE_MESSAGE_TYPES and s.get("DestinationSubscriber") and ep and ep != MHE_ENDPOINT_ID:
            found.setdefault(ep, []).append(CONSOLE_MESSAGE_TYPES[mtype])
    result = [{"endpoint": ep, "sections": sorted(set(v))} for ep, v in found.items()]
    _endpoint_cache[org.upper()] = (datetime.now().timestamp(), result)
    return result


def _endpoint_state(org, token, endpoint_id):
    try:
        r = requests.get(f"https://{API_HOST}{ENDPOINT_STATUS_PATH}?endpointId={endpoint_id}", headers=_mawm_headers(org, token), timeout=10, verify=False)
        if r.status_code != 200:
            return "Offline"
        body = r.json() or {}
        return (body.get("data") or {}).get("status") or body.get("status") or "Unknown"
    except Exception:
        return "Offline"


@app.route('/api/endpoints_status', methods=['POST'])
def endpoints_status():
    """Status of every endpoint the console's messages pass through."""
    data = request.json
    org = data.get('org', '').strip()
    token = data.get('token', '').strip()
    if not org or not token:
        return jsonify({"success": False, "error": "ORG and token required"})
    try:
        eps = expected_endpoints(org, token)
    except Exception as e:
        eps = [{"endpoint": MHE_ENDPOINT_ID, "sections": ["All (source)"]}]
        print(f"[ENDPOINTS] subscriber lookup failed: {e}")
    from concurrent.futures import ThreadPoolExecutor
    with ThreadPoolExecutor(max_workers=8) as pool:
        states = list(pool.map(lambda e: _endpoint_state(org, token, e["endpoint"]), eps))
    for e, st in zip(eps, states):
        e["status"] = st
    return jsonify({"success": True, "endpoints": eps})

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
    
    template, parser_error = get_parser_template(org, token, "Olpn_Loaded") if org and token else (None, "not signed in")
    message = generate_loading_message(pairs, org=org, template=template)
    if not message:
        return jsonify({"success": False, "error": "Failed to generate message"})
    
    result = {
        "success": True, 
        "message": message, 
        "pairs_used": pairs,
        "parser": parser_info(template, parser_error, "Olpn_Loaded", message["Message"][0])
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

# === FALLBACK: Serve index.html for SPA ===
@app.route('/', defaults={'path': ''})
@app.route('/<path:path>')
def serve_static(path):
    return send_from_directory(os.path.dirname(os.path.dirname(__file__)), 'index.html')

if __name__ == '__main__':
    app.run(debug=True, port=5000)

