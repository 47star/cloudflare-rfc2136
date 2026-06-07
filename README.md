# Cloudflare DDNS RFC2136 Bridge

This project is a stateless Rust service that accepts RFC2136 Dynamic DNS Update messages and applies permitted A and AAAA changes to the Cloudflare DNS API.

Architecture:

```text
DHCP server or RFC2136 DDNS client
  -> RFC2136 Dynamic DNS Update
  -> Rust service
  -> Cloudflare DNS API
```

The service has no domain, zone, suffix, credential, or Cloudflare setting compiled into the binary. Runtime configuration comes only from environment variables.

## Supported DNS Behavior

- UDP and TCP DNS listeners.
- RFC2136 UPDATE messages only.
- TSIG authentication is required.
- TSIG failures return REFUSED.
- Only the configured DNS zone is accepted.
- Only records below `ALLOWED_RECORD_SUFFIX` are accepted.
- Zone apex, wildcard names, first-label underscore names, and out-of-zone names are refused.
- A and AAAA are the only accepted record types.
- SOA, NS, MX, TXT, SRV, CNAME, PTR, and every other type are refused.
- RFC2136 prerequisite sections are refused because the bridge is stateless.

## Environment Variables

| Name | Required | Example | Notes |
| --- | --- | --- | --- |
| `LISTEN_UDP` | yes | `0.0.0.0:53` | UDP listener address. |
| `LISTEN_TCP` | yes | `0.0.0.0:53` | TCP listener address. |
| `DNS_ZONE` | yes | `example.internal.` | Accepted zone, fully qualified. |
| `ALLOWED_RECORD_SUFFIX` | yes | `example.internal.` | Accepted owner-name suffix. |
| `CLOUDFLARE_ZONE_ID` | yes | `replace-me` | Cloudflare zone id. |
| `CLOUDFLARE_API_TOKEN` | yes | `replace-me` | Cloudflare API token. Never logged. |
| `DEFAULT_TTL` | yes | `300` | TTL used for Cloudflare records. |
| `TSIG_KEY_NAME` | yes | `ddns-key.` | TSIG key name. |
| `TSIG_SECRET` | yes | `base64-encoded-secret` | Base64 TSIG shared secret. Never logged. |
| `TSIG_ALGORITHM` | yes | `hmac-sha256` | `hmac-sha256`, `hmac-sha384`, or `hmac-sha512`. |
| `LOG_LEVEL` | yes | `info` | Any valid `tracing_subscriber` env-filter value. |

## TSIG Key Generation

Generate a shared secret:

```sh
openssl rand -base64 32
```

Use that value as `TSIG_SECRET`. A BIND/nsupdate-style key file would look like this:

```conf
key "ddns-key." {
    algorithm hmac-sha256;
    secret "base64-encoded-secret";
};
```

The service itself never shells out for TSIG validation.

## Cloudflare API Token

Create a Cloudflare API token scoped to the target zone with:

- Zone: DNS: Edit

Use the resulting token as `CLOUDFLARE_API_TOKEN`, and set `CLOUDFLARE_ZONE_ID` to the target Cloudflare zone id.

## Docker

Build:

```sh
docker build -t cloudflare-ddns-rfc2136:local .
```

Run on port 5353:

```sh
docker run --rm \
  -p 5353:5353/udp \
  -p 5353:5353/tcp \
  -e LISTEN_UDP=0.0.0.0:5353 \
  -e LISTEN_TCP=0.0.0.0:5353 \
  -e DNS_ZONE=example.internal. \
  -e ALLOWED_RECORD_SUFFIX=example.internal. \
  -e CLOUDFLARE_ZONE_ID=replace-me \
  -e CLOUDFLARE_API_TOKEN=replace-me \
  -e DEFAULT_TTL=300 \
  -e TSIG_KEY_NAME=ddns-key. \
  -e TSIG_SECRET=base64-encoded-secret \
  -e TSIG_ALGORITHM=hmac-sha256 \
  -e LOG_LEVEL=info \
  cloudflare-ddns-rfc2136:local
```

For container port 53 with a non-root runtime user, grant `NET_BIND_SERVICE` or use Kubernetes security context as shown in `k8s/deployment.yaml`.

## Kubernetes

Review the example Secret first, then apply:

```sh
kubectl apply -f k8s/configmap.yaml
kubectl apply -f k8s/secret.yaml
kubectl apply -f k8s/deployment.yaml
kubectl apply -f k8s/service.yaml
```

The service manifest exposes both UDP and TCP port 53.

## VyOS DHCP DDNS Example

VyOS 1.5 DHCP server supports RFC2136 DDNS with TSIG. The example below sends forward-domain changes to this bridge. Replace `192.0.2.53` with the service address that routes to the Kubernetes Service or Docker host.

```text
set service dhcp-server dynamic-dns-update
set service dhcp-server dynamic-dns-update send-updates enable
set service dhcp-server dynamic-dns-update conflict-resolution disable
set service dhcp-server dynamic-dns-update tsig-key ddns-key. algorithm hmac-sha256
set service dhcp-server dynamic-dns-update tsig-key ddns-key. secret base64-encoded-secret
set service dhcp-server dynamic-dns-update forward-domain example.internal. key-name ddns-key.
set service dhcp-server dynamic-dns-update forward-domain example.internal. dns-server 1 address 192.0.2.53
set service dhcp-server dynamic-dns-update forward-domain example.internal. dns-server 1 port 53
set service dhcp-server shared-network-name LAN dynamic-dns-update qualifying-suffix example.internal.
```

This bridge accepts A and AAAA forward records only. Reverse domains and PTR records are refused by design.
