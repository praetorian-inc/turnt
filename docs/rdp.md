
# 🖥️ Connecting via RDP using the TURNt Admin Console

The `TURNt Admin Console` provides a streamlined interface for managing **local port forwarding** over an active TURNt SOCKS proxy. This feature allows you to expose internal network services—like RDP (Remote Desktop Protocol)—on your local system for direct access through `localhost`.

---

## 🧰 Prerequisites

Ensure the following are set up:

- A running `turnt-controller` instance with SOCKS5 proxy available on `127.0.0.1:1080`.
- A connected `turnt-relay` on the remote host.
- The `turnt-admin` binary is built and available on your local system.
- A stable TURN tunnel has been established via prior controller/relay handshake.

---

## 🚀 Procedure: Forwarding RDP for Local Access

### 1. Start the Admin Console

Launch the admin utility:

```bash
turnt-admin
```

You should see:

```
[INFO] Connecting to admin server at localhost:1337
[INFO] Connected to admin server
TURNt Admin Console
Type 'help' for available commands
Type 'exit' to quit
>
```

---

### 2. Add a Local Port Forward for RDP

To map a remote host’s RDP service (e.g., `192.168.1.38:3389`) to your local port (e.g., `3389`), run:

```bash
> lportfwd add 3389 192.168.1.38:3389
```

✅ This creates a tunnel from your machine’s `localhost:3389` to the remote internal asset over the TURN tunnel.

📌 *You can verify with:*

```bash
> lportfwd list
Local port 3389 → 192.168.1.38:3389
```

---

### 3. Connect Using Your RDP Client

Open your preferred RDP client and connect to:

```
localhost:3389
```

You should now be accessing the remote host (`192.168.1.38`) as if it were on your local network.

---

### 4. Remove the Forward When Finished

Clean up the port forward to free resources:

```bash
> lportfwd remove 3389
```

---

## 🧠 Notes and Tips

- **Do not use `rportfwd`** for this case. RDP requires connections *initiated from the local side*, so only `lportfwd` is appropriate.
- You can create multiple simultaneous forwards if needed:
  
  ```bash
  lportfwd add 13389 192.168.1.105:3389
  lportfwd add 13390 192.168.1.106:3389
  ```

- Ensure that the SOCKS5 proxy and TURN tunnel are stable during the session.

---

## 📋 Admin Console Command Reference

```bash
> help
Available commands:
  lportfwd add <local_port> <remote_ip>:<remote_port>  # Add a new local port forward
  lportfwd remove <local_port>                          # Remove a local port forward
  lportfwd list                                         # List all local port forwards
  rportfwd add <port> <target>                          # Add a new remote port forward (used for reverse connections)
  rportfwd remove <port>                                # Remove a remote port forward
  rportfwd list                                         # List all remote port forwards
  exit                                                  # Exit the admin console
```

---

## 🌐 Admin Server Technical Details

The TURNt Admin Console communicates with the TURNt controller via a custom **QUIC-based admin server**.

### Key Characteristics:

- **Protocol:** QUIC (Quick UDP Internet Connections)
- **Transport:** UDP
- **Listening Address:** `localhost:1337/UDP`
- **No authentication:** Currently the administrative interface doesn't enforce authentication and thus only binds to the localhost interface on 1337/UDP

This allows operators to interact with the TURNt controller using a low-latency, multiplexed protocol that blends in with modern traffic patterns and provides robust handling for multiple concurrent command types (e.g., port forwarding management).

> ⚠️ Ensure that your local firewall or endpoint protections allow UDP traffic on port 1337 to facilitate successful connections.

---

## 🛠️ Admin Console CLI Options

The `turnt-admin` binary provides the following command-line options for configuration:

```bash
Usage of turnt-admin:
  -addr string
        Admin interface address (default "localhost:1337")
  -verbose
        Enable verbose logging
```

### Example:

To run the admin console with verbose logging and connect to a custom address:

```bash
turnt-admin -addr 127.0.0.1:1337 -verbose
```
