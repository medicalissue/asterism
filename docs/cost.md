# `ast cost` — what your agent is actually spending

An agent that runs unattended is worth exactly as much as the keys you are
willing to hand it. What stops people handing over the key is not knowing what
it will do with one.

Asterism answers that with a number, not with a limit. Every model API call an
instance makes through a bound secret already passes through this device's
egress door, and the provider's answer already carries its own token counters.
`ast cost` reads them back.

**There is no quota, no allowlist, and no cap anywhere in this feature, and
there is not going to be one.** Nothing in the ledger path can refuse, throttle
or delay a call. If accounting fails — a full disk, a read-only home — the call
still succeeds and the daemon says so in its log. Accounting is the by-product;
the call is the product.

## Using it

```
$ ast cost bot
today      $4.12   1.21M in · 83k out · cache 940k   claude-sonnet-5 (312 calls)
this week  $19.80

$ ast cost --all --today
bot     $4.12
bot-2   $1.03

$ ast cost bot --json
{"instance":"bot","window":"today","since":1756272000,"usd":4.12,...}

$ ast ls
NAME   STATUS   IMAGE  SHAPE  DEVICE   AGE  TODAY  ACCESS
bot    running  ...                         $4.12  ...
```

| flag | window |
|---|---|
| *(none)* | today, plus this week as a second line |
| `--today` | since local midnight |
| `--week` | since local midnight six days ago — seven days including today |
| `--since 6h` | a duration ending now: `90s`, `30m`, `6h`, `7d` |
| `--all` | every instance on the device in front of you |
| `--json` | one JSON object per instance, on its own line |

`ast cost <name>` is routed like every other instance command: it reaches
whichever device in the orbit supplies that instance's compute, because that is
the device whose door read the counters. `--all` is deliberately device-local —
it asks the machine in front of you what it has been paying for.

The `TODAY` column in `ast ls` is filled from the device you typed the command
on. An instance whose compute comes from another device shows `-` there; ask
its own device with `ast cost <name>`, which routes.

## Where the numbers come from

The secrets egress door already terminates a bound guest's TLS on the host
(`docs/adr/0004-chv-egress-door.md`). One call in
`crates/asterism-daemon/src/egress.rs`, after the answer is in hand, reads
integers out of bytes that are already in memory on their way back to the
guest. Nothing new is intercepted and nothing new is decrypted.

Understood today:

| shape | fields read |
|---|---|
| Anthropic Messages | `usage.input_tokens`, `output_tokens`, `cache_creation_input_tokens`, `cache_read_input_tokens` |
| Anthropic Messages, streaming | `message_start` for input and cache, the last `message_delta` for output |
| OpenAI Chat Completions | `usage.prompt_tokens`, `completion_tokens`, `prompt_tokens_details.cached_tokens` |
| OpenAI Responses | `usage.input_tokens`, `output_tokens`, `input_tokens_details.cached_tokens` |
| OpenAI streaming | the final chunk's `usage` (`stream_options: {include_usage: true}`) |
| anything else | the call, and its request and response byte counts |

Detection is **shape first, path second**. Agents are routinely pointed at a
gateway — `ANTHROPIC_BASE_URL`, an OpenAI-compatible router, a company proxy —
and a ledger that went blank the moment somebody did that would be worse than
no ledger, because it would be silently wrong rather than obviously absent. A
response carrying a recognisable `usage` object and a model name is read as
that provider's call whatever host answered it.

Two normalisations are worth knowing about:

* **Cached input is separated from fresh input.** Anthropic's `input_tokens`
  already excludes the cached part; OpenAI's `prompt_tokens` includes it. The
  ledger stores the Anthropic convention for both, so one pricing row reads
  either. Recording OpenAI's total as fresh input would bill cache reads at ten
  times what they cost.
* **Non-2xx answers are not recorded.** A 401 is the shape of a key that
  stopped working, and counting it would make a broken key look like a
  spending one.

An unbound host is carried by a blind tunnel — two sockets and a copy, no
certificate, nothing read — so nothing about it is recorded and nothing about
it could be.

## Storage

```
$ASTERISM_HOME/instances/<name>/cost/2026-08-27.jsonl
```

One JSON object per line, one line per call, one file per local calendar day.

```json
{"ts":1756300000,"provider":"anthropic","host":"api.anthropic.com","model":"claude-sonnet-5","calls":1,"input_tokens":1000,"output_tokens":200,"cache_write_tokens":300,"cache_read_tokens":4000,"request_bytes":512,"response_bytes":4096}
```

**No request body, no response body, no header, no prompt, no completion, no
handle and no secret is in a ledger line**, and no code path exists that could
put one there: the extractor returns integers, and integers are what the entry
type holds. `crates/asterism-core/src/ledger.rs` has a test that enumerates
every key a line may carry, so a field added later has to be argued for there.

Append-only, one `write` per line under `O_APPEND`, no read-modify-write: a
crash loses at most the line that was in flight, and a torn tail is skipped on
read rather than making the day unreadable. Rotation is the filename — reading
a week opens seven small files, and forgetting a month is `rm`.

The ledger travels with `ast backup` and comes back with `ast restore`, so
moving an instance between machines does not reset its history. The rest of
`instances/<name>/` — seeds, agent keys, sockets, the egress directory — stays
where it is; the backup allowlist in `crates/asterism-core/src/backup.rs` is
the redaction boundary and each entry on it is a decision.

## Prices

`crates/asterism-core/src/pricing.json` is compiled in, dated, and USD per
million tokens:

```json
{ "prefix": "claude-sonnet-5", "input": 2.0, "output": 10.0,
  "cache_write": 2.5, "cache_read": 0.2 }
```

Matching is by longest prefix, so `claude-sonnet-4-5-20250929` is priced by the
`claude-sonnet-4-5` row: a provider publishing a new dated snapshot of a model
whose price has not moved must not blank the column.

**A model no row matches is reported in tokens with no dollar figure** — `-` in
the table, `"usd": null` in the JSON, and a line at the bottom saying the total
is a floor. A guessed rate would be indistinguishable from a real one in the
output, and the first time it was wrong nobody would believe the ones that were
right.

Rates move on somebody else's schedule and an Asterism release is not on it.
Write the same shape to `$ASTERISM_HOME/pricing.json` to correct a row or add a
model:

```json
{
  "updated": "2027-03-01",
  "models": [
    { "prefix": "claude-sonnet-5", "input": 1.5, "output": 7.5 },
    { "prefix": "my-local-llama", "input": 0.0, "output": 0.0 }
  ]
}
```

A row whose prefix already exists replaces it; a new prefix is added. The file
is read once when the daemon starts, so a correction takes a restart. A row
that omits `cache_write` or `cache_read` bills cache tokens at the input rate —
approximately right beats free.

`ast cost --json` reports `priced_at`, the date the table was true, so a stale
figure can always be told from a fresh one.

## What is not covered

* **Calls that do not go through a bound secret.** If an agent holds a raw key
  of its own and reaches the API through the guest's ordinary NAT, the door
  never sees it and neither does the ledger. `ast attach <name> --secret` is
  what puts a call on this path.
* **Anything the provider does not report.** Nothing here is estimated from
  body length. A response with no `usage` is a call and a byte count.
* **Day boundaries on Windows are UTC.** The local offset comes from the
  platform timezone database on Unix; the Windows path has no equivalent yet
  and rolls the day over at UTC midnight.
* **Orbit-wide totals.** `ast cost <name>` routes to one device. Summing an
  orbit is a report nobody has asked for yet.
