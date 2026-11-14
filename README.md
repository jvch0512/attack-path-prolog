# attack-path-prolog

attack-path answers one question security teams ask constantly and rarely can prove: starting from what is exposed to the internet, which chains of vulnerabilities and trust relationships reach the assets that matter, and which single fix cuts the most paths. You describe the estate as a short list of facts, and the Prolog engine does the reasoning.

**Live demo:** https://jvch0512.github.io/attack-path-prolog/ (A made-up estate: web, app, jump host, file server, database and a backup server.)

SWI-Prolog 9 (swipl), no packages beyond plunit for tests. The demo page is rendered from the tool's `--tsv` output by `scripts/site.py` (Python 3, only needed to regenerate the page).

## Use

```bash
make test
./bin/attack-path examples/estate.facts
./bin/attack-path examples/estate.facts --tsv
./bin/attack-path examples/estate.facts --max-hops 5 --fail-on high   # exit 1 in CI
```

Facts file (one fact per line, ends with a dot):

```prolog
asset(web1, dmz, normal).          % asset(Name, Zone, normal|crown)
asset(db1, data, crown).
exposed(web1, https).              % reachable from the internet
vuln(web1, 'CVE-2024-0001', rce).  % rce | auth_bypass | privesc | info_leak
link(web1, app1, ssh_key).         % link(From, To, Via): network reach or stolen trust
```

A link whose `Via` is `ssh_key`, `password`, `token`, `kerberos` or `trust` needs no vulnerability on the target. Any other link (plain network reach) needs an `rce`, `auth_bypass` or `privesc` vulnerability on the target.

| Finding | Severity | Meaning |
|---|---|---|
| PATH | critical (2 hops or fewer), high (3), medium (4), low (more) | a complete chain from the internet to a crown asset, listed step by step |
| CHOKE | high | a host that sits on at least half of all paths, so fixing it breaks the most chains |

See [examples](examples) and [docs/sample-output.txt](docs/sample-output.txt).

## Limits

- It reasons only over the facts you write. Missing facts mean missing paths, so treat "no path" as "no path in this model".
- Facts are a model, not a scan: pair it with real inventory and vulnerability data, such as [vuln-prioritizer](https://github.com/jvch0512/vuln-prioritizer).
- Paths are simple (no host is visited twice) and limited by `--max-hops` (default 6).
- The facts file is parsed as data. Directives and rules are rejected, nothing in it is executed.

## Where it fits

Pre-sales and architecture reviews: turning a questionnaire into a defensible attack-path picture, prioritising remediation by paths cut rather than by CVSS alone, and explaining segmentation value to a non-technical buyer.

## Tests

```bash
make test    # 22 plunit tests
```

MIT.
