# 📘 TURNt + Zoom: Credential Extraction & Proxy Setup Guide

## 🧭 Overview

This document details the process of extracting TURN credentials from the Zoom web client using interception tools such as Burp Suite, for use with the TURNt toolkit to establish command-and-control or SOCKS proxy channels. While currently a manual process, it is straightforward to execute and credentials are typically valid for several days.

> ⚠️ This process should be performed in a browser instrumented for interception — for example, the built-in Chromium browser shipped with Burp Suite — to ensure Zoom traffic is captured for analysis.

---

## 🛠️ Step-by-Step Instructions

### Step 1: Authenticate via Zoom Desktop App

1. Launch the Zoom desktop application.
2. Click the **Host** dropdown.
3. Select **With Video Off** to start a meeting.

<div align="center">
  <img width="877" alt="Zoom Host Menu" src="https://github.com/user-attachments/assets/5d9ffe33-c4fc-4734-82e4-75253fe7e334" />
</div>

This launches a new Zoom meeting session.

---

### Step 2: Switch to the Zoom Web Client

1. Wait for the launch meeting page to appear.
2. Click **Join from your browser**.

<div align="center">
  <img width="642" alt="Join From Browser" src="https://github.com/user-attachments/assets/ca08f34a-a122-48b4-a205-c29b39620dc3" />
</div>

This ensures you're using the Zoom Web Client, which is easier to inspect and intercept.

> 🧩 Ensure that Burp Suite (or your interception proxy of choice) is actively monitoring traffic.

---

### Step 3: Join the Meeting

Once the browser client loads, you will be placed into the meeting.

<div align="center">
  <img width="875" alt="In the Meeting" src="https://github.com/user-attachments/assets/862c7878-5b6f-4386-8a76-b3058393e1e2" />
</div>

No further interaction is needed here — keep the session active.

---

### Step 4: Intercept `zak` Request and TURN Credentials

1. Monitor your intercepted traffic for a request containing a `zak` token. This appears to be sent by the client to authenticate and we've noted the response to this message always includes TURN credentials. 

<div align="center">
  <img width="870" alt="JWT Request" src="https://github.com/user-attachments/assets/f5e745d0-41cf-4cf5-ab13-4ef29522047f" />
</div>

2. Identify the response from the server to the previous message sent by the client. This returned JSON blob should contain TURN credentials for Zoom servers that we can leverage within TURNt. The credentials are within the `mediasdkConfig` field within the returned JSON blob.

<div align="center">
  <img width="905" alt="TURN Response" src="https://github.com/user-attachments/assets/c32a9bf5-acbd-4d91-8ba0-f6db8e74d27a" />
</div>

---

### Step 5: Beautify the JSON Response

To format the response for easier inspection:

```bash
pbpaste | jq
```

This will output a readable JSON structure. Locate the following:

```json
"mediasdkConfig": {
  "iceServers": [
    {
      "urls": "turns:turnsg01.cloud.zoom.us:443?transport=tcp",
      "username": "...",
      "credential": "..."
    },
    {
      "urls": "turns:turnsg02.cloud.zoom.us:443?transport=tcp",
      "username": "...",
      "credential": "..."
    }
  ]
}
```

---

### Step 6: Convert to TURNt Configuration

Copy the `iceServers` block and convert it to the following YAML format:

```yaml
ice_servers:
  - urls:
      - turns:turnsg01.cloud.zoom.us:443?transport=tcp
    username: "USERNAME_HERE"
    credential: "CREDENTIAL_HERE"
  - urls:
      - turns:turnsg02.cloud.zoom.us:443?transport=tcp
    username: "USERNAME_HERE"
    credential: "CREDENTIAL_HERE"
```

Save the above as `config.yaml` and use it with TURNt as described in the [TURNt documentation](#).

✅ This configuration enables TURNt to route SOCKS5 traffic through Zoom's TURN infrastructure for covert communications.

---

## ✅ Summary

- Authenticate using the Zoom client, then switch to the browser-based Zoom Web Client.
- Intercept traffic containing `zak` tokens and `mediasdkConfig` via a proxy like Burp.
- Extract and reformat TURN credentials into a YAML config for TURNt.
- Use TURNt to establish a SOCKS5 proxy over Zoom TURN infrastructure.
