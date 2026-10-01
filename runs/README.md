# Checked-in eval runs

These files are the fail-closed admit / deny / escalate record. Read them here. A review does not need a live Ollama or Nimble process.

| File | Role |
| --- | --- |
| [`fail-closed-unsupported.json`](fail-closed-unsupported.json) | Review record: `seed`, `model`, admit / deny / escalate counts, `timestamp`, `reproduce`, and `nimble` |
| [`e2e-demo-fail-closed.json`](e2e-demo-fail-closed.json) | Stdout of that same run (`e2e-demo.report.v1`) |

## This run

The scorer was missing. `npm run --silent e2e-demo` targeted `http://127.0.0.1:9` and exited 2.

- `seed` is null. This path does not sample. The pin is `dataset.sha256` of `packages/authority-flip/data/pairs.jsonl`.
- `model` is `unsupported`.
- `decision` is `unsupported`. `closure` is `deny-closed`.
- `admit` / `deny` / `escalate` count gate choices on the 32 pair sides: 0 / 32 / 0. Every `reasonCode` is `fail_closed_down`. The stub did not run.
- `timestamp` is the report `generatedAt`.
- `nimble.status` is `unsupported`. `flip_rate` and `ece` are null, copied from that comparator. The same nulls are on `base-qwen` and `frontier-judge` in the source report.
- `soft_pass` is false. The message states that Soft-PASS was refused.

## Honesty

Nimble score ≠ gate held. Live flip/ECE was deferred until this artifact (no Soft-PASS substitute).

The deny counts are the gate client's fail-closed path. The authority-flip harness left flip rate and ECE null when Ollama did not answer, and this snapshot leaves those fields null. High noul ≠ safe. This is not AdaptiveSandbox. This is not open Jev.

## Reproduce

The command below is the `reproduce` string. Exit 2 is the missing-scorer result. Stdout is the e2e report. `TYPESAFE_API_KEY=ollama` is the local placeholder from the gate client docs. Ollama ignores it. It is not a host credential. The judge key stays unset, so the judge stays `unsupported` and no key is written into the report.

```bash
env -u AUTHORITY_FLIP_JUDGE_API_KEY -u OLLAMA_HOST \
  TYPESAFE_BASE_URL=http://127.0.0.1:9 \
  TYPESAFE_API_KEY=ollama \
  TYPESAFE_DEFAULT_MODEL=nimble \
  AUTHORITY_FLIP_OLLAMA_BASE_URL=http://127.0.0.1:9 \
  AUTHORITY_FLIP_TIMEOUT_MS=2000 \
  GATE_TIMEOUT_SECONDS=1 \
  npm run --silent e2e-demo
```

Install the Python packages once so the gate path can record the deny-closed rows. The root [README](../README.md) demo section has that install. `npm test` checks the checked-in files. It does not call Ollama.
