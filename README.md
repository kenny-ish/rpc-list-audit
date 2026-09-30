# rpc-list-audit

Checks the public EVM RPC lists that wallets and sites copy from, [chainlist.org](https://chainlist.org) and
[ethereum-lists/chains](https://github.com/ethereum-lists/chains), for entries that cannot work. It only reports
failures that look the same wherever you run it from. A timeout from one server says little about an endpoint,
while a hostname that no longer exists in DNS is missing for everyone.

```
$ python audit.py
7587 rpc entries on 2882 chains, 5792 hostnames
1077 hostnames gone from DNS
1214 dead entries on 859 chains

1 Ethereum Mainnet
  wss://ethereum.callstaticrpc.com
      hostname gone from DNS (NXDOMAIN at Cloudflare and Google)
  https://api.securerpc.com/v1
      hostname gone from DNS (NXDOMAIN at Cloudflare and Google)

3 Ropsten  (every listed entry is dead)
  https://ropsten.infura.io/v3/9aa3d95b3bc440fa88ea12eaa4456161
      hostname gone from DNS (NXDOMAIN at Cloudflare and Google)
...
```

That run is from 29 September 2026. On 410 of those 859 chains no listed entry works at all, which usually
means the chain itself has shut down.

## What counts as dead

| check | reported when |
|---|---|
| DNS | the local resolver cannot find the host, and DoH at Cloudflare and Google both answer NXDOMAIN for A and AAAA |
| `--probe`: HTTP 410 | the endpoint says it is gone |
| `--probe`: Cloudflare 520 to 527 | Cloudflare cannot reach the origin server |
| `--probe`: API key errors | "invalid api key", "unknown token", "api key required" and similar, typically a key embedded in the URL that no longer works |
| `--probe`: wrong chain | `eth_chainId` answers with a different chain than the one the entry is listed under |

Timeouts, 429s, other 5xx responses and connection resets are counted as inconclusive and left out of the
report, because they depend on your network and the moment you ask. The local resolver only decides which
hosts get double-checked. A host is never reported on the local answer alone.

```
$ python audit.py --chain 1 --chain 10 --probe
106 rpc entries on 2 chains, 80 hostnames
4 hostnames gone from DNS
probed 87 https endpoints: 56 ok, 5 dead, 26 inconclusive (not reported)
9 dead entries on 2 chains
...
10 OP Mainnet
  https://optimism.meowrpc.com
      hostname gone from DNS (NXDOMAIN at Cloudflare and Google)
  https://go.getblock.io/e8a75f8dcf614861becfbcb185be6eb4
      API key error: "Unknown token"
  https://endpoints.omniatech.io/v1/op/mainnet/public
      Cloudflare 521, origin unreachable
  https://optimism.lava.build
      HTTP 410 Gone
...
```

Before removing anything from a list, run it a few times over a day or so. A domain can lapse and come back,
and a Cloudflare error can be a short outage. The cleanup PRs this was written for,
[DefiLlama/chainlist#3181](https://github.com/DefiLlama/chainlist/pull/3181) and
[ethereum-lists/chains#8771](https://github.com/ethereum-lists/chains/pull/8771), only included endpoints that
failed the same way on repeated runs.

## Usage

```bash
python audit.py                                   # chainlist.org/rpcs.json, DNS check only
python audit.py --source ethereum-lists           # chainid.network/chains.json
python audit.py --source ethereum-lists --field faucets
python audit.py --chain 8453 --probe --json base.json
python audit.py --file rpcs.json                  # a local copy of either list
```

Standard library only. `--probe` sends one `eth_chainId` request to every https endpoint that resolves, so
narrow it with `--chain` unless you mean to contact a few thousand servers.

## Tests

```bash
python -m unittest -v
```
