# SZL governed kernels

[![kernel contracts](https://github.com/szl-holdings/szl-kernels-live/actions/workflows/kernel-contracts.yml/badge.svg)](https://github.com/szl-holdings/szl-kernels-live/actions/workflows/kernel-contracts.yml)

An inspectable release surface for the ten public
[`SZLHOLDINGS` Hugging Face Kernels](https://huggingface.co/SZLHOLDINGS).

This repository does not call documentation a benchmark. It records:

- the exact 40-character Hugging Face revision for every kernel;
- every published `build/torch-cpu` file, Git object ID, size, and SHA-256;
- the import package, dependencies, compatibility boundary, and probe;
- an explicit source-binding status and retirement/replacement status;
- limitations that remain visible next to the artifact;
- a real CPU import/probe receipt covering all ten pinned revisions;
- negative tests that reject mutable revisions, altered digests, and invented
  driver support.

## Verified snapshot

Recorded 2026-07-26:

| Evidence | Result | Meaning |
|---|---:|---|
| Public Kernel Hub inventory | 10/10 | All ten public artifacts were enumerated from the Hugging Face API. |
| Exact live-head match | 10/10 | Each live head matched its reviewed 40-character pin at capture time. |
| File-content integrity | 10/10 | Every `build/torch-cpu` file matched its checked SHA-256. |
| Revision-pinned imports/probes | 10/10 | Every package imported and its declared functional probe passed on CPU. |
| Hugging Face driver declarations | 0/10 | No CUDA/ROCm driver family is declared; none is inferred here. |
| Exact public GitHub source binding | 0/10 | Three related source repositories are linked, but byte-equivalence is not claimed. |

The receipt is
[`evidence/kernel-selfcheck-20260726.json`](evidence/kernel-selfcheck-20260726.json).
It records Windows amd64, Python 3.11, CPU execution, and Torch 2.10 for the
Torch-dependent packages. It is not a GPU, performance, security, or
independent-audit receipt.

## Portfolio shape

- **Flagship experimental:** `szl-kernels`
- **Active experimental:** `szl-govsign`, `szl-lambda-gate`, `szl-blocked`,
  `szl-provctl`, `szl-invariants`, `szl-ouroboros`, `szl-formulas`
- **Retained compatibility:** `szl-governed-norm`,
  `governed-inference-meter`; the dedicated GitHub repositories are archived
  and `szl-kernels` is the replacement direction

These are Python governance kernels. They are not model weights, training
artifacts, CUDA/Triton speed kernels, or evidence of autonomous decision
authority.

## Developer verification

Offline contract and refusal checks:

```bash
python scripts/verify_kernel_registry.py
python -m unittest discover -s tests -v
```

Live head, file-set, and SHA-256 verification:

```bash
python scripts/verify_kernel_registry.py --live
```

Real revision-pinned imports and declared probes:

```bash
python scripts/verify_kernel_registry.py \
  --live \
  --run-imports \
  --receipt evidence/kernel-selfcheck-20260726.json
```

Torch is required for `szl-kernels`, `szl-lambda-gate`, and
`szl-governed-norm`; `cryptography` is required for `szl-govsign`.
`pynvml` is optional. Without a real NVML meter, energy remains
`UNMEASURED`.

The snapshot generator never advances a revision automatically:

```bash
python scripts/snapshot_kernel_contracts.py
```

An update requires a human-reviewed change to
[`registry/kernel-pins.json`](registry/kernel-pins.json), regeneration, live
verification, and review of the resulting file-digest diff.

## Loading contract

Hugging Face Kernels execute repository code, so use both a full revision and
the explicit trust flag:

```python
from kernels import get_kernel

kernel = get_kernel(
    "SZLHOLDINGS/szl-kernels",
    revision="06cc46f9733a844ee1c4cab558b06b3bd2d377ea",
    trust_remote_code=True,
)
result = kernel.selfcheck()
assert result["ok"] is True
```

Do not replace the revision with `main` in production or demonstrations.

## Boundaries

- Lambda uniqueness remains **Conjecture 1 (open)**. The gate is advisory.
- Functional self-checks are not independent security or correctness audits.
- No CUDA, ROCm, throughput, latency, numerical-stability, or energy benchmark
  is claimed by this snapshot.
- `szl-blocked` proves its default-deny path without executing the protected
  callable; it does not prove policy completeness.
- Source links marked `RELATED_GITHUB_SOURCE` are related source, not a
  byte-for-byte provenance claim.
- The seven `HF_REVISION_PINNED_GITHUB_SOURCE_OPEN` entries remain release
  work: their immutable Hugging Face source is inspectable, but no exact public
  GitHub source binding was found.

## License

Apache-2.0 for this registry, verifier, tests, and site. Each kernel retains the
license published with its own artifact.
