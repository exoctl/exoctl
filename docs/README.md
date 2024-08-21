### API Documentation

Documentation engine for detect malwares and better laboratory maldec labs

### Dependencies

For compile engine necessary : asio, yara, pkg-config, libpq, libsqlite3

---

### Overview
This API provides WebSocket-based endpoints for scanning data and searching within the system. The service is designed to handle real-time communication, ensuring efficient data transfer and processing. Below are the details for each available route, along with their respective functionalities.

---

### Endpoints

#### 1. **Search Endpoint**
- **Route:** `/search`
- **Method:** WebSocket (POST)

**Description:**
This endpoint establishes a WebSocket connection to allow clients to perform search operations. 

**WebSocket Events:**
- **onaccept:** Validates the connection request. (Currently, validation is planned for future implementation.)
- **onopen:** Initiates context-specific resources upon connection.
- **onclose:** Cleans up resources when the connection is closed.
- **onmessage:** Handles incoming messages. Depending on the data type (binary or text), different operations might be performed.

**Logging:**
- Upon creation, a log entry confirms the route has been established.

---

#### 2. **Scan Endpoint**
- **Route:** `/scan`
- **Method:** WebSocket (POST)

**Description:**
This endpoint allows clients to send data for scanning via a WebSocket connection. The scanning process involves applying certain rules to determine whether the data is malicious.

**WebSocket Events:**
- **onaccept:** Validates the connection request. (Validation implementation is planned.)
- **onopen:** Establishes resources needed when a connection is opened.
    - Response connection is sucessful `{"status": "ready"}`
- **onclose:** Handles the cleanup of resources when the connection closes.
- **onmessage:** Processes incoming data, triggering a scan. The scan results, including whether the data is malicious and any applicable rules, are sent back to the client.

**Scanning Process:**
- When data is received, a new scan instance is created.
- Rules are loaded and applied to the data.
- Upon scan completion, the system logs the result and sends a JSON response back to the client. This response includes whether the data is considered malicious and the rule that triggered the result.

**Logging:**
- A log entry is made for each of the following events:
  - Route creation
  - Rule loading
  - Scan completion, including the size of the scanned data.

---

### WebSocket Connection Context
The API uses WebSocket events to manage the connection lifecycle:
- **SOCKET_OPEN_CONNECTION_CONTEXT:** Handles any initialization required when a WebSocket connection is established.
- **SOCKET_CLOSE_CONNECTION_CONTEXT:** Manages the cleanup when the connection is terminated.


This documentation provides a concise overview of how to interact with the API's WebSocket routes for search and scan functionalities. For more details on error handling and custom implementation, refer to the internal codebase or contact the support team.