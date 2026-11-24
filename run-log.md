# Run Log

Running record of every test run: what was tried, settings, results, and observations.
Newest entries at the bottom.

---

## Run 1 — 2026-11-24 — first end-to-end run (baseline, unmodified code)

**Goal:** confirm the unmodified fork runs on local Ollama and returns valid JSON.

| Setting | Value |
|---|---|
| Date | 2026-11-24 (06:31–06:35 UTC) |
| Code | upstream `f77fe7c`, unmodified |
| Analyzer | `logsentinelai-httpd-access`, batch mode |
| Input | first 4 lines of `sample-logs/access-10k.log` |
| Chunk size | 2 (→ 2 chunks) |
| Model | `qwen2.5:3b` (Q4_K_M) via Ollama 0.40.17, CPU only, context 8192 |
| Hardware | i5-1235U, 16 GB RAM, no GPU |
| Command | `uv run logsentinelai-httpd-access --log-path "$env:TEMP\access-4.log" --chunk-size 2` |

**Results**

| Chunk | Time | Prompt tokens | Response tokens | Valid JSON / schema | Verdict |
|---|---|---|---|---|---|
| 1 | 135 s | 2019 | 754 | ✅ / ✅ | INFO, no attack |
| 2 | 68 s | 1923 | 535 | ✅ / ✅ | INFO, no attack |

Total: about 3.5 minutes for 4 lines. Chunk 1 includes model load time; chunk 2 is closer to steady state (~34 s/line).

**Verdict check (manual):** both verdicts are correct. These lines are AhrefsBot, Bingbot and normal image requests, so INFO is right.

**Observations**
1. **Chunk 1 extraction error:** `source_ips` lists only `31.56.96.51` and `unique_ips: 1`, but the chunk has 2 IPs. `54.36.149.41` (AhrefsBot) was dropped. This is a counting error on clean logs, before any attack, and shows the baseline accuracy matters.
2. **Possible hallucination, chunk 2:** the summary says the traffic is from the United States, but GeoIP was disabled and nothing in the logs says so. The model inferred or invented it.
3. **Metadata bug:** `@log_path` says `sample-logs/access-10k.log`, but the file analyzed was `%TEMP%\access-4.log`. The `--log-path` argument isn't reflected in the output metadata.
4. **Relevant to task 2:** the prompt already wraps log lines in `<LOGS BEGIN>` / `<LOGS END>`, but nothing tells the model that the text between them is untrusted data. A log line can also contain the literal text `<LOGS END>` and fake the end of the log block.
5. **Speed:** at about 34 s/line, the full 10k-line file would take days on this laptop. Evaluation sets must stay small, or move to the 7B on a faster machine or the Claude API.
6. Elasticsearch send failed as expected (not running); Telegram skipped (disabled).
