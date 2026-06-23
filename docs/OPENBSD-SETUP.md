# OpenBSD Setup for foss.violetskysecurity.com

Concrete provisioning steps. Run in order. Approximate time: 2-3 hours
including OS install and ACME cert issuance.

Assumes OpenBSD 7.6 or newer (for Go 1.22+ in packages). All commands run
as `root` unless prefixed with `doas -u <user>` or noted otherwise.

## 0. Before you start

- DNS for `foss.violetskysecurity.com` must point at the host's public IP.
- Port 80 and 443 must be reachable from the public internet (port 80 for
  ACME http-01 challenge, port 443 for production traffic).
- You have an OpenBSD install ISO and console access (KVM, IPMI, or
  physical).

## 1. Base OpenBSD install

Use the OpenBSD installer's defaults except:

- Hostname: `foss.violetskysecurity.com`
- User account: create one (e.g. `rudi`) with `doas` privileges.
- Disk: full disk install, default partitioning is fine for POC.
- Sets: minimum is `bsd*`, `comp*`, `xbase*`, `xfont*`, `xshare*` — install
  all default sets, you'll want `comp` for development.
- `sshd(8)`: yes, enable.
- `xenodm(1)`: no, this is a headless server.

After install, reboot, log in as your user, then:

```sh
doas syspatch       # apply security patches
doas pkg_add -u     # update packages
```

## 2. Install build dependencies

```sh
doas pkg_add go git
```

This installs Go (currently 1.22 or newer in -current) and Git. That's
genuinely all the toolchain you need for this POC — `go build` does
everything else.

Verify:

```sh
go version
git --version
```

## 3. Create service users

Each service runs as a dedicated unprivileged user with no shell. They
share a group (`_sptcommon`) for socket directory access.

```sh
doas groupadd -g 9000 _sptcommon

doas useradd -u 9001 -g _sptcommon -d /var/spt-txn/tr      -s /sbin/nologin -L daemon _spttr
doas useradd -u 9002 -g _sptcommon -d /var/spt-txn/a/wlt   -s /sbin/nologin -L daemon _sptaw
doas useradd -u 9003 -g _sptcommon -d /var/spt-txn/a/cat   -s /sbin/nologin -L daemon _sptaci
doas useradd -u 9004 -g _sptcommon -d /var/spt-txn/a/cap   -s /sbin/nologin -L daemon _sptacp
doas useradd -u 9005 -g _sptcommon -d /var/spt-txn/a/tts   -s /sbin/nologin -L daemon _sptat
doas useradd -u 9006 -g _sptcommon -d /var/spt-txn/b/ver   -s /sbin/nologin -L daemon _sptbv
doas useradd -u 9007 -g _sptcommon -d /var/spt-txn/b/res   -s /sbin/nologin -L daemon _sptbr
doas useradd -u 9008 -g _sptcommon -d /var/spt-txn/audit   -s /sbin/nologin -L daemon _sptaud
```

## 4. Create directory layout

```sh
doas mkdir -p /var/spt-txn/{tr,audit}
doas mkdir -p /var/spt-txn/a/{wlt,cat,cap,tts,keys}
doas mkdir -p /var/spt-txn/b/{ver,res,keys}
doas mkdir -p /var/spt-txn/sockets

# Ownership
doas chown _spttr:_sptcommon  /var/spt-txn/tr
doas chown _sptaw:_sptcommon  /var/spt-txn/a/wlt
doas chown _sptaci:_sptcommon /var/spt-txn/a/cat
doas chown _sptacp:_sptcommon /var/spt-txn/a/cap
doas chown _sptat:_sptcommon  /var/spt-txn/a/tts
doas chown root:_sptcommon    /var/spt-txn/a/keys
doas chown _sptbv:_sptcommon  /var/spt-txn/b/ver
doas chown _sptbr:_sptcommon  /var/spt-txn/b/res
doas chown root:_sptcommon    /var/spt-txn/b/keys
doas chown _sptaud:_sptcommon /var/spt-txn/audit
doas chown root:_sptcommon    /var/spt-txn/sockets

# Permissions
doas chmod 700 /var/spt-txn/{a,b}/keys
doas chmod 770 /var/spt-txn/{tr,audit,sockets}
doas chmod 770 /var/spt-txn/a/{wlt,cat,cap,tts}
doas chmod 770 /var/spt-txn/b/{ver,res}
```

## 5. Generate offline signing keys with signify(1)

These are the trust-anchor keys. Generate them on the host and protect with
strong passphrases.

```sh
# Trust Registry's own signing key (signs registry updates)
doas signify -G -n -p /var/spt-txn/tr/registry.pub \
                     -s /var/spt-txn/tr/registry.sec
doas chown root:_sptcommon /var/spt-txn/tr/registry.{pub,sec}
doas chmod 640 /var/spt-txn/tr/registry.pub
doas chmod 600 /var/spt-txn/tr/registry.sec

# Domain A CT issuer key (will be wrapped later for Ed25519 signing)
doas signify -G -n -p /var/spt-txn/a/keys/ct-issuer.pub \
                     -s /var/spt-txn/a/keys/ct-issuer.sec

# Domain A TTS issuer key
doas signify -G -n -p /var/spt-txn/a/keys/tts-issuer.pub \
                     -s /var/spt-txn/a/keys/tts-issuer.sec

# Domain B verifier doesn't sign anything inbound, but signs audit roots
doas signify -G -n -p /var/spt-txn/b/keys/audit.pub \
                     -s /var/spt-txn/b/keys/audit.sec

# Domain A audit key
doas signify -G -n -p /var/spt-txn/a/keys/audit.pub \
                     -s /var/spt-txn/a/keys/audit.sec
```

Note: `signify(1)` generates Ed25519 keys but uses its own file format. The
Go services will read these and convert to raw Ed25519 at startup. Don't
generate keys with `openssl` — use `signify` so OpenBSD's hardened key
generation is in the chain.

Also generate raw Ed25519 keys for the Go services that don't use signify
format directly. The `scripts/gen-service-keys.sh` script in this repo
handles that.

## 6. ACME cert for foss.violetskysecurity.com

OpenBSD ships `acme-client(1)` and a default `/etc/acme-client.conf`. Edit
the conf to add your domain:

```sh
doas vi /etc/acme-client.conf
```

Add this domain block:

```
domain foss.violetskysecurity.com {
    domain key "/etc/ssl/private/foss.violetskysecurity.com.key"
    domain full chain certificate "/etc/ssl/foss.violetskysecurity.com.fullchain.pem"
    sign with letsencrypt
}
```

Then run httpd briefly to serve the http-01 challenge. The simplest path is
to use OpenBSD's bundled `/etc/httpd.conf` ACME template; copy from
`/etc/examples/httpd.conf` and uncomment the ACME server block.

```sh
doas cp /etc/examples/httpd.conf /etc/httpd.conf
doas vi /etc/httpd.conf
```

Edit so the `acme` server block listens on port 80 for your domain. Then:

```sh
doas rcctl enable httpd
doas rcctl start httpd
doas acme-client -v foss.violetskysecurity.com
```

If successful, cert and key are at the paths in the conf. If not, check
the DNS A record is correct and port 80 is reachable.

Add to cron for renewal:

```sh
doas crontab -e
# Add line:
# 0 0 * * * acme-client foss.violetskysecurity.com && rcctl reload relayd
```

## 7. Configure relayd as TLS terminator and reverse proxy

```sh
doas vi /etc/relayd.conf
```

```
table <trust_registry>    { /var/spt-txn/sockets/trust-registry.sock }
table <domain_a_wallet>   { /var/spt-txn/sockets/a-wallet.sock }
table <domain_a_cat>      { /var/spt-txn/sockets/a-cat.sock }
table <domain_a_cap>      { /var/spt-txn/sockets/a-cap.sock }
table <domain_a_tts>      { /var/spt-txn/sockets/a-tts.sock }
table <domain_b_verify>   { /var/spt-txn/sockets/b-verify.sock }
table <domain_b_execute>  { /var/spt-txn/sockets/b-execute.sock }

http protocol "https" {
    tls keypair foss.violetskysecurity.com

    match request header set "X-Forwarded-For"   value "$REMOTE_ADDR"
    match request header set "X-Forwarded-Proto" value "https"

    pass request path "/tr/*"  forward to <trust_registry>
    pass request path "/a/wallet*"   forward to <domain_a_wallet>
    pass request path "/a/cat*"      forward to <domain_a_cat>
    pass request path "/a/cap*"      forward to <domain_a_cap>
    pass request path "/a/tts*"      forward to <domain_a_tts>
    pass request path "/b/verify*"   forward to <domain_b_verify>
    pass request path "/b/execute*"  forward to <domain_b_execute>

    block return 404
}

relay "wwwtls" {
    listen on 0.0.0.0 port 443 tls
    protocol "https"
    forward to <trust_registry>
}
```

Place certs where relayd expects:

```sh
doas cp /etc/ssl/foss.violetskysecurity.com.fullchain.pem \
        /etc/ssl/foss.violetskysecurity.com.crt
doas cp /etc/ssl/private/foss.violetskysecurity.com.key \
        /etc/ssl/private/foss.violetskysecurity.com.key
# (paths must match the relayd tls keypair name)

doas rcctl enable relayd
doas rcctl start relayd
```

Verify `relayd` is running and serving the cert:

```sh
echo | openssl s_client -connect foss.violetskysecurity.com:443 -servername foss.violetskysecurity.com 2>/dev/null | openssl x509 -noout -subject -issuer
```

Should print the Let's Encrypt issuer and your CN.

## 8. Firewall

```sh
doas vi /etc/pf.conf
```

Append (or merge with existing rules):

```
# SPT-Txn POC: allow ssh, http (acme), https
pass in proto tcp from any to (egress) port { 22 80 443 }

# Block everything else inbound
block in log
```

Reload:

```sh
doas pfctl -f /etc/pf.conf
```

## 9. Clone the POC repo

```sh
cd /usr/local/src
doas mkdir spt-txn-poc
doas chown rudi spt-txn-poc
git clone <your-poc-repo-url> spt-txn-poc
cd spt-txn-poc
```

(For now, copy the files from this skeleton manually.)

Run the test suite:

```sh
go test ./...
```

Should see green tests for `internal/trustregistry/` and `internal/keys/`.

## 10. What you have at this point

- A hardened OpenBSD host with TLS terminated by `relayd` on port 443.
- Service users created, directory structure laid down with correct
  ownership and permissions.
- Signify keys generated for trust anchors.
- Go toolchain ready.
- POC repo cloned and initial test suite passing.

You're now ready to build the actual services in the order documented in
[`BUILD-ORDER.md`](BUILD-ORDER.md). The first thing to build is the Trust
Registry, because everything else depends on it.

## Troubleshooting

**`acme-client` fails with "http-01: no answer".** DNS hasn't propagated,
or port 80 is blocked. Check `dig foss.violetskysecurity.com` and confirm
`pf` allows inbound 80.

**`relayd` won't start.** Check `/var/log/messages` and `/var/log/daemon`.
Most common: cert path mismatch in `/etc/relayd.conf` vs where you put the
files.

**`signify -G` prompts forever for a passphrase.** That's normal; type a
strong passphrase. For the POC you can use `-n` to skip the passphrase
(less secure, fine for development).

**Pledge violations at runtime.** A Go service is calling a syscall not in
its pledge set. Log will say which one. Either add it to the pledge set in
the service's `main.go` or restructure to avoid it.
