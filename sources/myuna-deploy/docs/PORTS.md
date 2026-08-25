# Port registry

| Environment | Port | Bind address | Exposure | State |
|---|---:|---|---|---|
| dev | 18080/TCP | 127.0.0.1 | WSL loopback only | manually active during approved v5 dev tests |
| staging | 18081/TCP | 127.0.0.1 | WSL loopback only | disabled |
| prod | 18082/TCP | 127.0.0.1 | WSL loopback only | disabled |
| PostgreSQL dev | 5432/TCP | localhost | WSL/Windows host only | active, synthetic data only |
| AstrBot dev WebUI | 6185/TCP | 127.0.0.1 | Windows/WSL host only | installed; manually active during channel setup |
| NapCat dev WebUI | 6099/TCP | 127.0.0.1 | Windows/WSL host only | installed; manually active during channel setup |
| OneBot v11 reverse WS | 6199/TCP | Docker bridge only | AstrBot/NapCat containers only | available only while the dev stack runs |

Owner enrollment uses `/run/myuna-gateway/challenge.sock`, a local Unix socket;
it adds no TCP/UDP listener and exists only during an explicitly approved
challenge window.

The Stage 4 retrieval worker does not use TCP or UDP. Its development transport
is the owner-only Unix socket `/run/myuna-retrieval-dev/worker.sock`; the unit is
installed disabled and the socket exists only while the unit is running. ADR-013
allows Core to use this socket only for explicit synthetic-memory test requests.

No Windows Firewall, Hyper-V Firewall, router, Radmin, or public ingress rule is
created for these ports. External exposure requires an architecture decision,
authentication design, reverse proxy, and explicit approval.

Ports 6099 and 6185 are published by Docker only on host loopback. Port 6199 is
not published on the WSL host; it is reachable only by containers attached to
the dedicated `myuna-astrbot-qq-dev` bridge. None of these ports may be opened
through Radmin, Windows Firewall, a router, or a public tunnel.

PostgreSQL must never listen on a LAN, Radmin, router, or public address. The
runtime role normally connects over the Unix socket with peer authentication;
TCP loopback exists for host-local administration and requires SCRAM.
