# Progress Telemetry and Reporting Views

Follow-up to `tasks/scoring-redesign.md` (complete). That task made the score correct.
This one makes it possible to see **when during a run** the score was earned, and adds the
two reporting views built on top of it.

## Goal

The primary chart for the benchmark plots weighted score against cost. Today vulnapps
records one cost figure per scan, so a run is a single point: it finished at $1,942 with
261 points. That supports a configuration comparison but not a shape — you cannot tell
whether a run earned 250 of those points by $800 and then crawled, or picked up a 27-point
chain at $1,900.

The end goal is a **trajectory view**: one line per run, stepping up at each finding,
ending where the run ended. Nothing extends past a run's endpoint, because cost is an
output, not an input.

That depends on COS emitting per-finding cost events, which it does not do yet. So this
task ships in two parts: an interim view that works on data we already have, and the
telemetry plumbing behind it.

**Non-goals:** no changes to scoring maths (settled in the previous task), no changes to
the matcher, no averaging of trajectories.

---

## Measurement rules this task assumes

Recorded here because they are protocol, and the code below only makes sense against them.
The full statement lives in the benchmark methodology doc.

- **Runs are not capped for measurement.** COS runs until it self-terminates. The $4K limit
  is a safety cap against runaway loops, not a budget level.
- **Cost is an output.** Each run spends what it spends. There are no budget levels to
  compare configurations at.
- **Only successful, self-terminated runs enter the dataset.** Runs that errored, were
  cancelled, or hit the $4K safety cap are excluded rather than recorded and filtered.
- **A run's line ends at its endpoint.** No carry-forward, no extrapolation, no averaging
  of curves with different lengths. If a run stopped at $1,200 there is nothing to plot
  beyond $1,200.
- **Minimum 5 trials per `config_fingerprint`** before a configuration is reported.

---

## Phase 1 — Interim reporting view (no dependencies)

Buildable today on `scans.cost` plus the weighted score from the previous task. This is the
view that goes in front of people until telemetry lands.

**Paired horizontal bars.** Two panels sharing one set of rows, one row per
`config_fingerprint`:

- left panel: final weighted score, bar length = mean across trials
- right panel: final cost, bar length = mean across trials
- whiskers on both, min to max across trials
- human reference runs and the DAST baseline appear as their own rows

- [ ] `GET /api/apps/{id}/comparison-bars` returning, per `config_fingerprint`: label,
      trial count, mean/min/max weighted score, mean/min/max cost.
- [ ] Frontend view rendering the paired panels.
- [ ] Reuses the existing Phase 8 guards. A configuration under 5 trials is shown with the
      guard banner, not silently.

**Do not ship an endpoint scatter** (one dot per run at final cost against final score).
It was prototyped and it misleads: same-coloured dots for one configuration line up on a
rising diagonal, which reads as a single run progressing rather than ten independent runs.
Two readers made that error on the mockup. Bars cannot be misread that way.

---

## Phase 2 — COS-side telemetry (external dependency, not vulnapps)

Recorded here so the dependency is visible. **This is work for the COS team, not for this
repo.** Nothing in Phase 3 can be populated until it lands.

COS must emit, per testing agent, an event at each scoring milestone:

- `agent_id`
- `cumulative_agent_cost` and `cumulative_agent_tokens` at the moment of the event
- `timestamp`
- which milestone (`surface`, `flaw`, `poc`, `impact`) and for which finding

Plus one terminating event per agent carrying its final cumulative cost and tokens.

Two notes for whoever picks this up on the COS side:

- Per-agent cumulative is fine and is the less invasive option. Agents run in parallel and
  need no shared counter. vulnapps reconstructs the assessment-wide figure by merging
  timelines on timestamp.
- If instrumenting all four milestones is too invasive for a first cut, emit at `flaw` and
  `impact` only. The curve gets coarser, roughly half the resolution, and nothing else
  breaks.

---

## Phase 3 — vulnapps ingestion (blocked on Phase 2)

- [ ] Migration `031_finding_progress.sql`:

```sql
CREATE TABLE finding_progress (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id           INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    finding_id        INTEGER REFERENCES scan_findings(id) ON DELETE CASCADE,
    milestone         TEXT,
    agent_id          TEXT,
    agent_cost        REAL,
    agent_tokens      INTEGER,
    cumulative_cost   REAL,
    cumulative_tokens INTEGER,
    elapsed_seconds   INTEGER,
    recorded_at       TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_fprogress_scan ON finding_progress(scan_id);
CREATE INDEX IF NOT EXISTS idx_fprogress_cost ON finding_progress(scan_id, cumulative_cost);
```

- [ ] `agent_cost` / `agent_tokens` are what COS reports, stored verbatim.
      `cumulative_cost` / `cumulative_tokens` are **computed by vulnapps on import** by
      merging every agent's timeline on `recorded_at` and summing the most recent
      per-agent figure across all agents at that instant. Store both; never overwrite the
      reported values.
- [ ] Import format extension in `tools/import_scan.py`: accept a progress event array
      alongside findings. Absent array is valid and means no telemetry, which must not
      fail the import.
- [ ] Events referencing a finding that did not survive matching are retained, with
      `finding_id` null. They still contribute cost to the timeline.
- [ ] A scan either has full telemetry or none. Partial telemetry is a bug in the emitter;
      flag it on the scan rather than plotting a truncated line.

---

## Phase 4 — Trajectory view (blocked on Phase 3)

- [ ] `GET /api/apps/{id}/trajectories` returning, per scan: ordered
      `(cumulative_cost, cumulative_weighted_score)` pairs and the endpoint.
- [ ] Chart: one thin line per run, stepped, ending at that run's endpoint. Emphasised
      marker at each endpoint. Colour by `config_fingerprint`, not by run.
- [ ] No mean line. No band. Ten lines per configuration, drawn individually.
- [ ] Human reference runs and DAST render as single markers on the same axes.
- [ ] Score at any point on a line is the weighted score accumulated so far, using the same
      milestone credit rules as the final score. A run's last point must equal its
      `scorings` row exactly — this is the correctness test for the whole feature.

- [ ] **Derived statistic: score lost to a $2K cap.** For each run, read the score it had
      reached at `cumulative_cost = 2000` and subtract from its final score. Mean the
      difference across runs in a configuration. Runs that terminated under $2K contribute
      zero. Expose as a number on the comparison view, not a chart.

This statistic is the reason the telemetry is worth building. Without it the ceiling
question can only be answered directionally: how many runs went over $2K, and what those
runs scored in total. That cannot distinguish a run that had banked everything by $1,400
from one that landed a chain at $1,900.

---

## Order of work

1. Phase 1. No dependencies, and it is what gets used in the meantime.
2. Phase 2 needs an owner on the COS side. Raise it early; everything else waits on it.
3. Phase 3, then Phase 4, once events are flowing.

## Verification

- [ ] Phase 1 renders correctly for a configuration with a single trial (guard banner, no
      whisker).
- [ ] A scan imported without a progress array behaves exactly as it does today.
- [ ] For a scan with telemetry, the final point of its trajectory equals its `scorings`
      row weighted score to the cent and the point.
- [ ] Merged cumulative cost across parallel agents at the terminating event equals
      `scans.cost`.
- [ ] The $2K statistic returns zero for a configuration whose runs all terminated below
      $2K.
