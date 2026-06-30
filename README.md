# newbnc

An FTP bouncer for glftpd. It relays TCP between a client and your FTP server and prepends an `IDNT` line so glftpd logs the real client IP instead of the bouncer's. Single process, `epoll`, non-blocking — no thread or fork per connection.

The integration is the whole point: ftpbnc opens the connection to glftpd and, before any client byte goes through, sends

```
IDNT *@<client_ip>:
```

(the `*` becomes the ident username when `-i` is on). The field after the IP is the reverse-DNS hostname, left empty here — so the trailing colon is load-bearing: it's what tells glftpd where the (empty) hostname starts, which is the only thing that keeps an IPv6 client address unambiguous, since the address carries its own colons. glftpd has to trust the bouncer's host for this to be accepted — add the ftpbnc machine to your bnc/identd allow list in `glftpd.conf`. If glftpd doesn't trust the source, it ignores IDNT and you get the bouncer IP in the logs, which is the usual "why isn't this working" answer.

## Build

```
make
```

`ftpbnc` has no dependencies. `genconfig` links OpenSSL (`-lcrypto`); if you only want the relay, `make ftpbnc`.

## Run

```
Usage: ftpbnc -d dest_host:port -b bind_host:port [-t title] [-v] [-i]
            [-C connect_ms] [-I ident_ms] [-L idle_ms]

  -d dest_host:port  Destination FTP server (IPv4/IPv6)
  -b bind_host:port  Local bind address and port (IPv4/IPv6)
  -t title           Process title prefix ("title: N users")
  -v                 Verbose/debug (no daemonize)
  -i                 Enable IDENT lookup to client (port 113)
  -C connect_ms      FTP server connect timeout in ms (default 10000)
  -I ident_ms        IDENT timeout in ms (default 2000)
  -L idle_ms         Idle timeout in ms (default 600000, 0 = unlimited)
```

Bounce port 21 on all interfaces to a glftpd on the same box:

```
./ftpbnc -b 0.0.0.0:21 -d 127.0.0.1:9021 -t newbnc
```

It daemonizes by default. Run with `-v` to keep it in the foreground with timestamped debug to stderr while you're sorting out a config. `-t` sets the prefix shown in `ps` — the daemon keeps the live user count appended, so `newbnc: 4 users`.

`-i` turns on an RFC1413 ident lookup back to the client (port 113). It's optional and time-boxed by `-I`; if the client has no identd it falls back to `*` and relaying still starts. Don't enable it expecting modern clients to answer — most won't.

## Encrypted config (optional)

If you don't want bind/dest sitting in the process args or a shell script in cleartext, `genconfig` builds a launcher with them encrypted (AES-256-GCM, key from your password via PBKDF2-HMAC-SHA256):

```
./genconfig -b 0.0.0.0:21 -d 127.0.0.1:9021 -t newbnc -o start.sh
```

It prompts for a password twice and writes `start.sh` with the config embedded as a hex blob. Running `./start.sh` asks for that password, decrypts, and execs `ftpbnc`. The launcher expects `genconfig` and `ftpbnc` to live in the same directory as itself, and forwards any extra args straight through (`./start.sh -v -L 0`). Lose the password, lose the config — there's no recovery, that's the point.

## Internals

One `epoll` loop drives everything. The unit is a connection that owns up to three endpoints — client, server, and (with `-i`) ident — each its own epoll registration. A wakeup carries a pointer to the endpoint, which back-references its connection, so routing a ready fd to the right handler is one dereference.

A new client triggers a non-blocking connect to the destination and, in parallel, the optional ident probe. Relaying does not start until both have resolved: only then is the `IDNT` line built and queued to the server as the first bytes, ahead of anything from the client. That ordering is load-bearing — glftpd reads IDNT as the opening line of the session.

Backpressure is per-direction watermarks. Each endpoint has an output buffer; when one side's pending output crosses 75% full, reads on the opposite side are disabled until it drains back under 25%. A slow client can't make the server-side buffer grow without bound, and vice versa.

The one thing that breaks silently: the `IDNT` line format. glftpd parses it positionally, so if you change `build_idnt_line` and the shape drifts from what glftpd expects, the bouncer keeps relaying fine and the only symptom is wrong IPs in the logs. Match glftpd's parser exactly.
