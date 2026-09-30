"""Find dead endpoints in public EVM RPC lists (chainlist.org, ethereum-lists/chains), counting only
failures that look the same from anywhere."""
import argparse
import concurrent.futures as cf
import http.client
import json
import re
import socket
import urllib.error
import urllib.request
from collections import defaultdict
from urllib.parse import urlparse

SOURCES = {
    "chainlist": "https://chainlist.org/rpcs.json",
    "ethereum-lists": "https://chainid.network/chains.json",
}
DOH = ("https://cloudflare-dns.com/dns-query", "https://dns.google/resolve")
KEY_ERRORS = re.compile(r"invalid api key|api key disabled|api key required|unknown token|key (?:has )?expired"
                        r"|not in white ?list", re.I)
CLOUDFLARE_DOWN = range(520, 528)
UA = "rpc-list-audit/1.0"


def endpoints(chains, field="rpc", chain_ids=None):
    """(chain_id, chain_name, url) for every entry of `field`. Works with both list formats:
    chainlist stores {"url": ..., "tracking": ...} objects, ethereum-lists stores plain strings."""
    out = []
    for c in chains:
        if chain_ids and c.get("chainId") not in chain_ids:
            continue
        for e in c.get(field) or []:
            url = e if isinstance(e, str) else (e or {}).get("url")
            if url and urlparse(url).hostname:
                out.append((c["chainId"], c.get("name", ""), url))
    return out


def get_json(url, timeout=20, headers=None):
    req = urllib.request.Request(url, headers={"User-Agent": UA, **(headers or {})})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.load(r)


def dns_verdict(statuses):
    """'gone' when every DoH answer is NXDOMAIN (status 3), 'exists' when any answer is NOERROR (0),
    'unclear' otherwise (SERVFAIL, timeouts)."""
    if statuses and all(s == 3 for s in statuses):
        return "gone"
    return "exists" if 0 in statuses else "unclear"


def check_dns(hosts, workers=32):
    """{host: verdict} for the hosts the local resolver cannot find. Each of those is asked again over
    DoH at Cloudflare and Google, for A and AAAA, so a flaky local resolver cannot mark a host dead."""
    def local_ok(host):
        try:
            socket.getaddrinfo(host, 443)
            return True
        except OSError:
            return False

    def verdict(host):
        try:
            return dns_verdict([get_json(f"{r}?name={host}&type={t}", headers={"accept": "application/dns-json"})
                                .get("Status") for r in DOH for t in ("A", "AAAA")])
        except (OSError, ValueError):
            return "unclear"

    with cf.ThreadPoolExecutor(workers) as ex:
        failing = [h for h, ok in zip(hosts, ex.map(local_ok, hosts)) if not ok]
    with cf.ThreadPoolExecutor(min(workers, 12)) as ex:
        return dict(zip(failing, ex.map(verdict, failing)))


def classify_response(status, body, chain_id):
    """Sort an eth_chainId reply into ("ok", ""), ("dead", reason) for failures that do not depend on
    where you ask from, or ("unclear", reason) for anything that might (rate limits, 5xx, timeouts)."""
    if status == 410:
        return "dead", "HTTP 410 Gone"
    if status in CLOUDFLARE_DOWN:
        return "dead", f"Cloudflare {status}, origin unreachable"
    m = KEY_ERRORS.search(body or "")
    if m:
        return "dead", f'API key error: "{m.group(0)}"'
    if status != 200:
        return "unclear", f"HTTP {status}"
    try:
        got = int(json.loads(body)["result"], 16)
    except (ValueError, KeyError, TypeError):
        return "unclear", "not a JSON-RPC reply"
    return ("ok", "") if got == chain_id else ("dead", f"answers for chain {got}, listed under {chain_id}")


def probe(url, chain_id, timeout=10):
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "eth_chainId", "params": []}).encode()
    req = urllib.request.Request(url, data=body, headers={"Content-Type": "application/json", "User-Agent": UA})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return classify_response(r.status, r.read(4096).decode(errors="replace"), chain_id)
    except urllib.error.HTTPError as e:
        return classify_response(e.code, e.read(4096).decode(errors="replace"), chain_id)
    except (OSError, ValueError, http.client.HTTPException) as e:
        return "unclear", type(e).__name__


def audit(chains, field="rpc", chain_ids=None, do_probe=False, workers=32):
    """Run the checks and return (endpoints, findings, probe_counts)."""
    eps = endpoints(chains, field, chain_ids)
    hosts = sorted({urlparse(u).hostname for _, _, u in eps})
    dns = check_dns(hosts, workers)
    findings = [{"chain": cid, "name": name, "url": url, "reason": "hostname gone from DNS (NXDOMAIN at Cloudflare and Google)"}
                for cid, name, url in eps if dns.get(urlparse(url).hostname) == "gone"]
    counts = defaultdict(int)
    if do_probe and field == "rpc":
        targets = [(cid, name, url) for cid, name, url in eps
                   if url.startswith("https://") and "${" not in url and urlparse(url).hostname not in dns]
        with cf.ThreadPoolExecutor(workers) as ex:
            for (cid, name, url), (kind, reason) in zip(targets, ex.map(lambda t: probe(t[2], t[0]), targets)):
                counts[kind] += 1
                if kind == "dead":
                    findings.append({"chain": cid, "name": name, "url": url, "reason": reason})
    return eps, findings, dict(counts)


def report(eps, findings, counts, field):
    per_chain = defaultdict(list)
    for f in findings:
        per_chain[(f["chain"], f["name"])].append(f)
    listed = defaultdict(int)
    for cid, _, _ in eps:
        listed[cid] += 1
    gone_hosts = {urlparse(f["url"]).hostname for f in findings if f["reason"].startswith("hostname gone")}
    lines = [f"{len(eps)} {field} entries on {len(listed)} chains, {len({urlparse(u).hostname for _, _, u in eps})} hostnames",
             f"{len(gone_hosts)} hostnames gone from DNS"]
    if counts:
        lines.append(f"probed {sum(counts.values())} https endpoints: {counts.get('ok', 0)} ok, "
                     f"{counts.get('dead', 0)} dead, {counts.get('unclear', 0)} inconclusive (not reported)")
    lines.append(f"{len(findings)} dead entries on {len(per_chain)} chains")
    for (cid, name), fs in sorted(per_chain.items()):
        note = "  (every listed entry is dead)" if len(fs) == listed[cid] else ""
        lines.append(f"\n{cid} {name}{note}")
        lines += [f"  {f['url']}\n      {f['reason']}" for f in fs]
    return "\n".join(lines)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--source", choices=SOURCES, default="chainlist", help="which public list to fetch (default: chainlist)")
    ap.add_argument("--file", help="read the list from a local JSON file instead of fetching it")
    ap.add_argument("--field", choices=("rpc", "faucets"), default="rpc")
    ap.add_argument("--chain", type=int, action="append", help="only check this chain id (repeatable)")
    ap.add_argument("--probe", action="store_true", help="also send eth_chainId to every https RPC that resolves")
    ap.add_argument("--json", metavar="PATH", help="write the dead entries to a JSON file")
    a = ap.parse_args(argv)
    if a.file:
        with open(a.file, encoding="utf-8") as f:
            chains = json.load(f)
    else:
        chains = get_json(SOURCES[a.source], timeout=60)
    eps, findings, counts = audit(chains, a.field, set(a.chain or []), a.probe)
    print(report(eps, findings, counts, a.field))
    if a.json:
        with open(a.json, "w", encoding="utf-8") as f:
            json.dump(findings, f, indent=1)


if __name__ == "__main__":
    main()
