# Evaluation

This folder measures how well ZeroCheck tells a real negative from a blind spot, using real attack recordings from [OTRF Security-Datasets](https://github.com/OTRF/Security-Datasets).

```bash
pip install -e '.[dev]'
python evaluation/run.py        # downloads ~6 MB into evaluation/.cache, writes RESULTS.md and results.json
```

The full generated numbers are in [RESULTS.md](RESULTS.md). This page explains the method and what the numbers mean.

## Method

1. **Data.** 14 Windows attack recordings (credential dumping, LOLBins, discovery, scheduled tasks and more), each containing Sysmon and Security logs. [`otrf.py`](otrf.py) maps the raw events to the ECS fields ZeroCheck uses.
2. **Ground truth.** For each recording the attack's process (for example `ntdsutil.exe`) was confirmed by hand in Sysmon EID 1 and Security 4688. The harness checks it again on every run.
3. **Faults.** Six faults are injected into each recording, one at a time. Each one hides the attack so a plain search returns zero results: sensor outage, ingestion lag, retention, parser drift, logging disabled, and access denied.
4. **Questions asked.** For every case ZeroCheck answers "did the attack process run on this host during the recording?". On faulted data the right answer is `INSUFFICIENT_VISIBILITY`. On clean data, searching for a process that never ran must return `VERIFIED_NEGATIVE`; anything else is a false warning.
5. **Baseline.** Treating zero results as "didn't happen" accepts all 84 faulted searches as clean: 0% detected.

## Findings

**Checks that don't depend on a threshold work.** Parser drift, logging disabled, access denied and retention were detected in 56 of 56 cases, and ingestion lag in 13 of 14. None of these checks produced a single false warning on clean data at any threshold. Every false warning came from the silence check.

**The silence check is the weak part, and the data shows why.** It flags a host that sent nothing for longer than `max_silence`. With a fixed threshold there is a direct trade-off:

| max_silence | 5s outages caught | False warnings on clean data |
|---|---|---|
| 1–3s | 14/14 | 6–9 of 14 |
| 5s | 10/14 | 3 of 14 |
| 8s+ | 8/14 | 0 of 14 |

The threshold has to be shorter than the outage to catch it. But real hosts go quiet on their own: the domain controller in the ntdsutil recording has natural silences of several seconds. A single fixed threshold cannot do both, so **learning each host's normal silence (per-host baselines) is the top roadmap item.**

**Read the 8s+ row carefully.** Several searched spans (5–17s) are shorter than those thresholds, so the silence check rarely fires there at all. Most outages "caught" at 8s+ were caught through `source_empty`, not `source_silent`. The next point explains why.

**Wrong reasons are mostly an artifact of short clips.** For outages, lag and retention, ZeroCheck often reported `source_empty` instead of the injected reason. These clips hold only one or two process-creation events, so the fault removed every EID 1 / 4688 event in the stored data, and "this event type is not stored at all" was literally true. The verdict was still correct. In a SIEM with weeks of history this would not happen, but this evaluation cannot show that.

**One "false warning" was real.** In `empire_schtasks_creation_execution_elevated_user` the host runs `shutdown.exe /r` at 21:59:06, sends nothing from 21:59:40 to 22:00:26, and `smss.exe` starts at 22:00:29. ZeroCheck flagged that window as blind, which is correct: nothing during the reboot was observable. It is recorded in [`datasets.yaml`](datasets.yaml) as a confirmed gap and counted separately, not as a false warning.

**One real miss shows a design trade-off.** In `psh_mavinject_dll_notepad` the attack happened 20ms before the Security channel's last event. The injected lag was about 0.5s, under the 1s ingestion tolerance, so ZeroCheck accepted the window. Any tolerance means a search of the last few moments can be missed, so for "what happened just now" searches a smaller tolerance, or a warning instead of silence, would be safer.

## Limitations of this evaluation

- **Scaled time.** Real deployments use thresholds of minutes. These recordings are seconds long, so thresholds were scaled to seconds. The mechanism is the same; the operational numbers will differ.
- **Small sample.** 14 recordings and one question type (`process_execution`). Results on other questions and longer recordings may differ.
- **Synthetic faults.** The faults are injected by removing or editing events. Real failures can be messier, such as partial loss or out-of-order delivery.
- **Parameters seen before writing this page.** The outage length and the 1–8s thresholds were fixed before the first run. The 15s and 30s thresholds and the per-source search span were added after it, and the reasons are given above and in RESULTS.md.
- **The memory backend only.** These runs use the in-memory backend. Elastic gives the same results on the unit-test lab, but this evaluation was not replayed through Elasticsearch.
