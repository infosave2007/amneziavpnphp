# AmneziaWG 2.0 host prerequisites

The `awg2` protocol (AmneziaWG 2.0) uses the `amneziawg` kernel module to
implement the WireGuard handshake with extra obfuscation parameters
(`Jc`, `Jmin`, `Jmax`, `S1-S4`, `H1-H4`, `I1-I5`). The container that the
panel deploys runs the `awg-quick` userspace tool, but the actual cipher
work happens in the host kernel.

This means that **before** an `awg2` server is deployed, the target host
must have:

1. The `amneziawg` kernel module loaded.
2. The matching userspace tools (so DKMS can rebuild the module on kernel
   upgrades).

The container ships its own copy of `awg`/`awg-quick` so you do **not** need
the userspace tools at runtime, but installing the DKMS package brings the
correct headers along the way and is the easiest path on Debian/Ubuntu.

## Ubuntu / Debian (recommended)

```bash
apt-get update
apt-get install -y software-properties-common
add-apt-repository -y ppa:amnezia/ppa
apt-get update
apt-get install -y amneziawg-dkms amneziawg-tools
modprobe amneziawg
lsmod | grep amneziawg            # should print one or more lines
```

DKMS will register the module and rebuild it automatically when the kernel
is upgraded.

## Verifying the install

```bash
awg --version                     # amneziawg-tools v1.0.20210914 (or newer)
modinfo amneziawg | head -3       # version + license info
```

## How the panel wires this together

The container is started with:

```text
docker run -d --privileged \
  --cap-add=NET_ADMIN --cap-add=SYS_MODULE \
  -v /lib/modules:/lib/modules \
  ...
```

`-v /lib/modules:/lib/modules` is what makes the host's `amneziawg.ko`
visible inside the container. If the host module is missing, `awg-quick up`
inside the container will fail with errors such as:

```
ip: RTNETLINK answers: Operation not supported
Unable to access interface: Protocol not supported
```

## Troubleshooting

- **`Operation not supported` when running `awg-quick up`** — the host is
  missing `amneziawg-dkms`, or DKMS failed to build against the running
  kernel. Run `dkms status` and reinstall.
- **Handshake never completes from AmneziaVPN client** — make sure
  `awg show wg0` on the server lists `s1`, `s2`, `s3`, `s4`, `h1-h4`, and
  `i1`. If `s3=0`/`s4=0` are reported and clients send non-zero values,
  the kernel will silently drop the packets.
