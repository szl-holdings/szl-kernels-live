# szl-kernels-live

**The governed-kernel suite hub.** One static page that links every live SZL kernel hologram —
with each tile's **LIVE / ROADMAP status fetched from the Hugging Face Spaces API in _your_
browser at page load**. A tile only shows **LIVE** when its Space runtime is actually `RUNNING`;
otherwise it is honest **ROADMAP**. If the API can't be reached, the tile says **UNKNOWN** —
never a fabricated green.

- **Live Space:** https://huggingface.co/spaces/SZLHOLDINGS/szl-kernels-live
- **Status:** ROADMAP → **LIVE** (hub live; member status is resolved live, never hardcoded).

## Members (status resolved live from HF)

| Hologram | What it shows | Backing kernel |
|---|---|---|
| [szl-provctl-live](https://huggingface.co/spaces/SZLHOLDINGS/szl-provctl-live) | Provenance-DAG verify (in-toto v1 / SLSA v1), re-hashed in-browser | [szl-provctl](https://huggingface.co/SZLHOLDINGS/szl-provctl) |
| [energy-attest-holo](https://huggingface.co/spaces/SZLHOLDINGS/energy-attest-holo) | Energy attestation — RED when meters are dead | [szl-kernels](https://huggingface.co/SZLHOLDINGS/szl-kernels) |
| [governed-norm-holo](https://huggingface.co/spaces/SZLHOLDINGS/governed-norm-holo) | willay refusal classifiers, inspectable | [szl-governed-norm](https://huggingface.co/SZLHOLDINGS/szl-governed-norm) |
| [lambda-gate-holo](https://huggingface.co/spaces/SZLHOLDINGS/lambda-gate-holo) | The Λ gate — Conjecture-1 explainer | [szl-lambda-gate](https://huggingface.co/SZLHOLDINGS/szl-lambda-gate) |
| receipt-chain-live | a11oy receipt-lake chain, in-browser SHA3 verify | [szl-receipt](https://huggingface.co/SZLHOLDINGS/szl-receipt) |
| szl-govsign-live | DSSE / in-toto signing, ECDSA P-256 in-browser | [szl-govsign](https://huggingface.co/SZLHOLDINGS/szl-govsign) |
| szl-blocked-live | honest-BLOCKED as a first-class state | [szl-blocked](https://huggingface.co/SZLHOLDINGS/szl-blocked) |

## Honesty doctrine (binding)

- **REPORTED** = status is the Hugging Face API's own answer, read client-side at page load —
  never hardcoded, never faked. **LIVE** requires runtime `RUNNING`; anything else is **ROADMAP**;
  an unreachable API is **UNKNOWN**.
- **Λ = Conjecture 1** — advisory, never proven. Energy MEASURED-only. honest-BLOCKED surfaced.
- **0 runtime CDN** — one vanilla-JS file.

## Deploy

Hugging Face **static** Space — the root `index.html` is served as-is.

## Estate

Part of the SZL Holdings estate: [szl-kernels](https://huggingface.co/SZLHOLDINGS/szl-kernels) ·
[a-11-oy.com](https://a-11-oy.com)

## License

Apache-2.0.
