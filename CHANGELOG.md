# Changelog

All notable changes to the 5G-DPOP project will be documented in this file.

## [Unreleased] - 2025-12-03

### Added
- **Frontend (Topology)**: Added interactive hover tooltips to network nodes.
    - **UE**: Displays SUPI, IP address, Uplink/Downlink packet counts, and total bytes.
    - **UPF**: Displays active session count, total packet drops (with red alert), and aggregated traffic volume.
    - **gNB**: Displays IP address and number of connected UEs.
- **Frontend (UI)**: Added Theme support (Light/Dark mode) with dynamic color switching.
- **Frontend (UX)**: Implemented responsive SVG design using `viewBox` to ensure the topology graph scales correctly with the browser window.
- **Frontend (Assets)**: Integrated `lucide-react` library for professional vector icons (Smartphone, Server, Radio, Globe).

### Changed
- **API Server (Topology)**: Overhauled the topology generation logic to support ULCL (Uplink Classifier) and N9 interface scenarios.
    - Implemented a **Two-Pass Processing** strategy to correctly identify node types.
    - Added logic to distinguish between **Access Peers** (gNBs sending uplink traffic) and **Core Peers** (PSA-UPFs receiving N9 traffic).
    - Prioritized `UplinkPeerIP` for accurate Radio Access Network identification.
- **Agent (Deployment)**: Identified requirement to bind the agent to the Docker bridge interface (`br-free5gc`) when running with `free5gc-compose` to correctly capture PFCP signaling.

### Fixed
- **API Server**: Resolved file corruption issues in `cmd/api-server/main.go` (duplicate/truncated content).
- **Frontend**: Restored SVG `<animate>` tags for traffic flow dots and drop alert pulses that were missing in the initial React port.
- **Topology Visualization**: Fixed a bug where the PSA-UPF (in a ULCL setup) was incorrectly rendered as a generic "Peer" (gNB icon) instead of a UPF. It is now correctly identified as a UPF node connected via the N9 interface.
- **Frontend (Layout)**: Increased vertical spacing between UPF nodes to prevent label overlap with N9 interface links.

### Test Api
```bash
curl http://localhost:8080/api/v1/topology
```