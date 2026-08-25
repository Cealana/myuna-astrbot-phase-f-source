# Selected Core upgrade readiness retry v1

After systemd reports the fixed Core unit as active/running, the loopback HTTP
listener can still briefly refuse connections while it binds. The fixed live
backend therefore retries only `127.0.0.1:18081/healthz` and `/readyz` within
the existing bounded readiness timeout. Only HTTP 200 succeeds. Connection
errors, non-200 responses, and timeouts remain fail-closed and enter the
journaled rollback path.

This change adds no caller-selectable host, port, path, timeout, command, unit,
or shell surface.
