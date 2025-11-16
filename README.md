# MHE Console - Web Application

**Version 2.0.0** - Major Release - Core Features Complete
- **Receiving Section**: Fully implemented with LPN validation (Status = '1000')
- **Putaway Section**: Fully implemented with LPN validation (Status = '3000') and Location validation (LocationTypeId = 'STORAGE')
- **Loading Section**: Fully implemented with OLPN validation (Status in '7200', '7400', '7600') and automatic Shipment extraction
- **Picking Section**: Placeholder (to be completed)
- **Endpoint Status Control**: Real-time status monitoring with clickable start/stop functionality
- **WMS Nomenclature**: Uses "Started", "Stopped", "Offline" terminology
- **Comprehensive Logging**: Full console output with timestamped, color-coded messages
- **Authentication**: Secure token-based authentication with automatic UI hiding on failure
- **Input Persistence**: localStorage for all section inputs (except ORG for security)
- **Responsive UI**: 2x2 grid layout with collapsible sections, fixed-height scrollable console

**Version 1.8.1** - Enhanced Endpoint Status UX
- Expanded clickable area to include "Endpoint Status:" label
- Larger, more prominent tooltips with better visibility
- Automatic endpoint status set to "Offline" on auth failure
- Status remains offline until successful re-authentication

**Version 1.8.0** - Clickable Endpoint Status Control
- Made endpoint status indicator clickable to start/stop endpoints
- Click "Started" status to stop the endpoint
- Click "Stopped" status to start the endpoint
- "Offline" status is not clickable (shows hover tooltip explaining why)
- Added hover tooltips: "Start Endpoint", "Stop Endpoint", or offline explanation
- Automatic status refresh after start/stop operations
- Console logging for start/stop operations

**Version 1.7.0** - Enhanced Endpoint Status with WMS Nomenclature
- Updated endpoint status to use WMS terminology: "Started", "Stopped", "Offline"
- "Offline" now indicates connection failure (no response or API error)
- "Started" = endpoint is running (green checkmark icon)
- "Stopped" = endpoint is stopped but reachable (orange circle icon)
- "Offline" = connection failure (gray X icon)
- Improved visual distinction between connection issues and stopped endpoints

**Version 1.6.0** - Endpoint Status API Integration
- Implemented real-time endpoint status checking using Device Integration API
- Endpoint status indicator now reflects actual endpoint state (Started/Stopped)
- Status is checked automatically after authentication
- Periodic status checks every 30 seconds while authenticated
- Uses GET `/device-integration/api/deviceintegration/service/endpoint/status?endpointId={EndpointId}`
- Maps "Started" status to "Online" (green) and "Stopped" to "Offline" (red)

**Version 1.5.0** - Loading Section Shipment Extraction & Section Status Indicators
- Updated Loading section to extract Shipment from OLPN validation API response
- Changed Loading input from "LPN,Shipment pairs" to just "OLPNs" (shipment auto-extracted)
- Added error handling for OLPNs missing shipment information
- Implemented section-specific status indicators next to each section title
- Section status messages now appear in their respective sections (Receiving, Putaway, Picking, Loading)
- Authorization success/failure messages remain in main status bar
- Status indicators clear automatically when input changes

**Version 1.4.0** - Loading Section Implementation
- Added LPN,Shipment pair support for Loading section
- Format: "LPN,Shipment; LPN,Shipment" (similar to Putaway section)
- Implemented OLPN validation API integration
- Validates OLPNs exist and have Status in ('7200', '7400', '7600')
- Enhanced console output to show OLPN validation requests/responses
- Updated error handling for Loading section validation failures

**Version 1.3.1** - Endpoint Status Indicator
- Added endpoint status indicator in header (right side)
- Icon-based design with checkmark/X symbols
- Currently hardcoded to "Online" (green) - ready for health check integration
- Clean, professional visual indicator for endpoint status

**Version 1.3.0** - Putaway Location Validation
- Added location validation API integration for Putaway section
- Validates locations exist and have LocationTypeId = 'STORAGE'
- Both LPN and Location validation now performed before message generation
- Enhanced console output to show separate LPN and Location validation requests/responses
- Updated error handling to distinguish between LPN and Location validation failures

**Version 1.2.1** - Layout and UX Improvements
- Fixed console panel resizing issue - now fixed height (250px) with internal scrolling
- Made header more compact to save vertical space
- Added Enter key support to all input fields (triggers Generate MHE Message)
- Improved console output scrolling behavior
- Reduced padding and font sizes for better space utilization

**Version 1.2.0** - UI Improvements and Putaway Validation
- Main UI sections hidden until successful authentication
- UI automatically hides on any authentication failure
- Console output order fixed: validation messages first, MHE message last
- Added LPN validation to Putaway section (Status = '3000')
- Putaway section now supports multiple LPNs with smart parsing
- Enhanced error handling for authentication failures

**Version 1.1.2** - Fixed Validation Response Parsing
- Fixed response parsing to check for lowercase 'data' field (not just 'Data')
- Removed redundant status check since query already filters by Status = '1000'
- Any LPN returned from query is automatically valid

**Version 1.1.1** - Validation Console Logging
- Added validation request/response logging to console output
- Fixed payload format to include Size and Page fields
- Updated query format to use lowercase "and" operator

**Version 1.1.0** - Receiving Section Enhancement
- Added support for multiple LPNs in Receiving section
- Smart parsing: supports spaces, commas, and semicolons as separators
- LPN validation before message generation (checks Status = '1000')
- Enhanced error messages showing valid/invalid LPNs
- Case-sensitive LPN handling

**Version 1.0.0** - Initial Release

Web-based console for building and testing MHE (Material Handling Equipment) messages. This tool allows you to generate and send test messages to Manhattan WMS APIs for conveyors, automation equipment, and other MHE systems.

## Setup Instructions

### 1. Environment Variables in Vercel

Add the following environment variables in your Vercel project settings:

#### Required:
- `MANHATTAN_PASSWORD` - Manhattan API password
- `MANHATTAN_SECRET` - Manhattan API client secret

### 2. Local Development

1. Install dependencies:
   ```bash
   npm install
   pip install -r requirements.txt
   ```

2. Set environment variables locally (create a `.env` file or export them):
   ```bash
   export MANHATTAN_PASSWORD="your_password"
   export MANHATTAN_SECRET="your_secret"
   ```

3. Run the development server:
   ```bash
   npm run dev
   # or
   vercel dev
   ```

### 3. Deployment

1. Connect your repository to Vercel
2. Add all environment variables in Vercel dashboard
3. Deploy!

## Features

### Core Functionality
- ✅ Authenticate with Manhattan API (same as other apps)
- ✅ Four sections: Receiving, Putaway, Picking, Loading
- ✅ Generate MHE messages (JSON format)
- ✅ Send MHE messages to Manhattan APIs
- ✅ Console output showing requests and responses
- ✅ localStorage persistence for input fields

### User Experience
- ✅ Full-screen layout (no scrolling required)
- ✅ 2x2 grid layout for sections
- ✅ Collapsible/expandable sections
- ✅ Real-time console output
- ✅ Modern dark theme UI
- ✅ Input validation (to be added per section)

### Sections

Each section has:
- **Input field**: Section-specific input (e.g., LPN for Receiving/Putaway)
- **Generate MHE Message**: Creates formatted JSON message
- **Send MHE Message**: Sends message to Manhattan API

**Current Status:**
- All sections have placeholder implementations
- Will be built out section by section as requirements are defined

## API Endpoints

- `POST /api/app_opened` - Track app open event
- `POST /api/auth` - Authenticate with Manhattan API
- `POST /api/generate_receiving` - Generate Receiving MHE message
- `POST /api/send_receiving` - Send Receiving MHE message
- `POST /api/generate_putaway` - Generate Putaway MHE message
- `POST /api/send_putaway` - Send Putaway MHE message
- `POST /api/generate_picking` - Generate Picking MHE message
- `POST /api/send_picking` - Send Picking MHE message
- `POST /api/generate_loading` - Generate Loading MHE message
- `POST /api/send_loading` - Send Loading MHE message

## Project Structure

```
MHE_console/
├── api/
│   ├── index.py          # Flask API endpoints
│   └── vercel.json       # Vercel configuration
├── index.html            # Frontend UI
├── server.js             # Express server (for local dev)
├── package.json          # Node.js dependencies
├── requirements.txt      # Python dependencies
└── README.md            # This file
```

## Workflow

1. **Authenticate**: Enter ORG and authenticate
2. **Select Section**: Choose Receiving, Putaway, Picking, or Loading
3. **Enter Input**: Enter section-specific input (e.g., LPN)
4. **Generate**: Click "Generate MHE Message" to create JSON
5. **Review**: Check generated message in console output
6. **Send**: Click "Send MHE Message" to send to API
7. **View Response**: See API response in console output

## Notes

- Input fields are saved in browser localStorage
- ORG is never saved (security)
- Console shows all requests and responses with timestamps
- Sections can be collapsed to focus on one at a time
- Full-screen layout optimized for testing workflow

