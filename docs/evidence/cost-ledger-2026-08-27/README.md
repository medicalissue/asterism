# Cost ledger on a real VZ guest — 2026-08-27 (AST-151)

`scripts/e2e-cost.sh` on this host, green. Four API calls made by a real guest
through the real vsock egress door, the ledger they filled, and the four
commands a user types to read it.

## Host

| | |
|---|---|
| machine | Apple Silicon MacBook Pro |
| os | macOS 26.5.2, Darwin 25.5.0 |
| backend | `vz` — `astd-vz`, built from source and ad-hoc signed by `scripts/sign-vz.sh` |
| image | `docker.io/library/nginx:alpine`, OCI rootfs, direct kernel boot |
| upstream | `httpbin.org` over real public TLS |
| binaries | this branch, debug |

Reproduce:

```
ASTERISM_GUEST_AGENT_ARTIFACT=<static aarch64 linux asterism-guest> \
  bash scripts/e2e-cost.sh
```

Paths in the captures below are rewritten to `$ASTERISM_HOME` and
`$CARGO_TARGET_DIR`; nothing else is edited.

## Files

| file | what it is |
|---|---|
| `e2e-cost.log` | the whole run, 23 assertions |
| `ledger.jsonl` | `$ASTERISM_HOME/instances/bot/cost/2026-08-27.jsonl` verbatim |
| `cost.txt` | `ast cost bot` |
| `cost-all.txt` | `ast cost --all --today` |
| `cost.json` | `ast cost bot --today --json` |
| `ls.txt` | `ast ls`, with the new `TODAY` column |

## How a call without an API key still proves the reading

The counters `ast cost` reports come out of the **response body** of a call the
guest made. So any server that returns the right bytes is a complete test of
the reading, and no key is needed to make one. `httpbin.org/base64/<b64>`
returns exactly the bytes it is handed, over a real public certificate, so the
guest asks a real HTTPS host — through the real bound secret, the real vsock
door, the real TLS termination and the real upstream leg — for a body shaped
like an Anthropic answer.

This is the same case as the one the feature is for: detection is shape-first
rather than keyed on `api.anthropic.com`, because agents are routinely pointed
at a gateway.

## Proves

* **The door fills the ledger.** Four calls out of a running guest produced
  exactly four lines under `instances/bot/cost/2026-08-27.jsonl`, rotated by
  local date, and nothing produced a fifth.
* **An empty ledger reads as empty.** `ast cost --all --today` said "no model
  API calls recorded" before a single call was made — asserted first, because
  a ledger that invented a number would be the worst bug this feature could
  have.
* **Anthropic non-streaming** is read whole: 1000 in, 200 out, 300 cache write,
  4000 cache read, model `claude-sonnet-5`.
* **Anthropic streaming (SSE)** is read across its frames: input and cache from
  `message_start`, output from the last `message_delta` — 2000 in, 500 out,
  50000 cache read, model `claude-opus-5`. The `output_tokens: 1` on
  `message_start` did not win over the 500 on the delta.
* **OpenAI Chat Completions** has its cached prompt taken out of fresh input:
  `prompt_tokens: 900` with `cached_tokens: 400` was recorded as 500 fresh
  input and 400 cache read, not 900 input. Recording the total would have
  billed cache reads at ten times what they cost.
* **An unreadable API is still counted**, as a call and its bytes:
  `{"ts":...,"host":"httpbin.org:443","calls":1,"response_bytes":50}` — no
  model, no tokens, no invented dollars.
* **No body byte, no handle and no Keychain value is in the ledger.** The run
  greps the ledger for markers planted inside each of the four response bodies
  (`the-body-marker`, `msg_costlane`, `chatcmpl-costlane`, `end_turn`), for the
  guest's opaque handle, and for the raw Keychain sentinel — then greps *every
  file* the lane wrote for the sentinel.
* **Unpriced is `null`, not zero.** One of the four calls used no known model;
  `unpriced_calls: 1`, and `ast cost` says in words that the total is a floor
  and where to add a rate.
* **The arithmetic.** `usd: 0.0557` for `claude-opus-5` 0.0475 +
  `claude-sonnet-5` 0.00555 + `gpt-4o` 0.00265, from the rates in
  `crates/asterism-core/src/pricing.json` dated `priced_at: 2026-08-27`.
* **`ast ls` carries it.** The `TODAY` column shows `$0.06` beside a running
  instance.
* **The ledger is portable.** `ast backup export` put `cost/2026-08-27.jsonl`
  in the manifest and did not put `egress/` there.

## Does not prove

* **Real Anthropic or OpenAI endpoints.** No API key was used and none of these
  bytes came from a model provider. What is proved is that the published
  *shapes* are read correctly; the shapes themselves are pinned by fixtures in
  `crates/asterism-core/src/usage.rs` (including real streaming frames) and
  driven through a real CONNECT and TLS termination against a local mock in
  `the_door_records_what_four_real_calls_cost_without_a_key`
  (`crates/asterism-daemon/src/egress.rs`). A regression in what Anthropic or
  OpenAI actually sends would not be caught by any of them.
* **Long-run rotation.** Only one calendar day was exercised on the real host.
  The day-boundary behaviour is unit-tested (`ledger::tests::each_local_day_gets_its_own_file`).
* **Windows.** The local-midnight offset is read from the platform timezone
  database on Unix only; the Windows path rolls the day at UTC and was not run
  here.
* **Orbit-wide totals.** One device. `ast cost <name>` routes to the device
  supplying that instance's compute, but a two-device run was not made.
* **Concurrency at volume.** The append is one `write` under `O_APPEND` and is
  unit-tested to 250 sequential lines; a many-guest write storm was not run.
* **Restore of the ledger on this host.** The export manifest was inspected;
  `ast backup import` was not run in this lane. Round-trip is covered by
  `backup::tests::the_cost_ledger_travels_with_a_backup_and_host_plumbing_does_not`.
