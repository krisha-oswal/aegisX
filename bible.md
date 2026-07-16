# AegisX — Team Bible
**Track locked: Problem Statement 2 — AI-Driven Correlation of Cybersecurity Telemetry & Transactional Behaviour**

This doc is the single source of truth for the next 5 days. If something you're about to build isn't in here, ask before you build it — every hour spent on something the rubric doesn't reward is an hour a competing team spent winning.

---

## 1. The one thing to internalize

PS2 is not "build a fraud detector" and it is not "build a SOC dashboard." It is specifically:

> **Correlate two data types — cyber telemetry and transactional behaviour — using AI, and explain the correlation.**

Everything in your build should be justifiable with the sentence: *"this exists because it correlates telemetry with transactions, or because it explains that correlation."* If a feature can't complete that sentence, it's decoration. Decoration is fine on Day 5 if there's time. It is not fine on Day 2.

Your current architecture (risk engine → telemetry correlator → XGBoost → SHAP → LLM → quantum module) is **already well-aligned** to this track. The judge notes below are about tightening it, not rebuilding it.

---

## 2. Rubric mapping — where you stand today

| Expected Outcome (from problem statement) | Status | Gap |
|---|---|---|
| Correlates cyber telemetry with transactional behaviour | ✅ Strong | None — this is your core loop, keep it central |
| Detects cyber threats **proactively** | ✅ Strong | Proactive telemetry-first flow correlates anomalies (e.g. port scan) to identity patterns before transaction alerts. |
| Identifies fraud patterns | ✅ Strong | Stage 1 Primary Risk Engine identifies broad transactional fraud patterns, which feed Stage 2. |
| Detects quantum-related attack indicators | ✅ Strong | Fuses PQC compliance telemetry directly into composite threat score via a +15% HNDL vulnerability risk multiplier. |
| Reduces false positives | ✅ Strong | Stage 2 Meta XGBoost performs Meta-Labeling over Stage 1 outputs using network telemetry to filter noise. |
| Explainable AI-driven threat intelligence | ✅ Strong | SHAP + LLM summary is exactly right — this is your most "judge-catnip" feature, protect it at all costs |

### Two-Stage Validation Metrics

- **Stage 1 — Primary Risk Engine (Recall-focused):** a transparent, rule-based heuristic over transaction-only features (amount, frequency, merchant risk). Validated against BankSim's ground-truth fraud labels (Threshold >= 20.0): **98.7% recall**, **39.9% precision** — by design, Stage 1 is meant to be noisy; it exists to make sure nothing suspicious is missed before richer context is applied.
- **Stage 2 — Meta XGBoost (Precision-focused):** consumes the Stage 1 score alongside cybersecurity telemetry, transaction features, and quantum-exposure signal. Currently achieves **97% accuracy, 90% recall** on the fused model. Of the **371 alerts** Stage 1 raised, Stage 2 correlation narrowed that down to **32 alerts** (27 true threats, 5 false positives) — this is the concrete mechanism behind your false-positive-reduction number, and it's now traceable end to end: heuristic → fused model → real number.

Two real gaps: **proactive (telemetry-first) detection**, and **quantum signal that's actually correlated, not just displayed**. Both are fixable without new tooling — see Section 4.

---

## 3. DO

- **Make the Orchestrator the actual brain.** Route telemetry, transactions, and quantum inventory through it as parallel inputs into one feature vector — not a linear chain where quantum is off to the side. This single change is your highest-leverage architectural fix.
- **Add a telemetry-triggered detection path.** Alongside "transaction exceeds threshold → pull telemetry," add "telemetry anomaly (e.g. privileged session + geo-impossible + new device) → check recent transactions." Even a simple second entry point into the same Orchestrator proves "proactive," which is explicitly named in the outcomes and currently missing.
- **Fuse quantum risk into the threat score, even lightly.** Simplest version: if an alert's telemetry touches an asset flagged in `pqc_inventory` as HNDL-vulnerable, add a small weighted bump to the composite score and say so in the LLM summary ("this session also touched a legacy-RSA endpoint flagged for quantum exposure"). This turns quantum from a separate tab into a correlated signal — exactly what the track asks for.
- **Quantify your false-positive reduction and put the number on the dashboard.** "94 of 100 alerts filtered as noise" is a concrete, memorable, judge-repeatable stat. Judges score dozens of projects — give them a number they can write down.
- **Protect the SHAP + LLM explainability pipeline above everything else.** If you have to cut scope anywhere, cut elsewhere first. "Explainable AI-driven threat intelligence" is in the outcome list verbatim — this is not optional polish, it's a named requirement.
- **Ground your data in BankSim + CICIDS2017 rather than pure synthetic generation** (decision locked in after the Section 2 rubric review) — real transaction distributions and real attack signatures, fused via a synthetic identity/linkage layer. See Section 5 for the exact fusion logic. Keep this injection pipeline sharp: it's what makes the correlation demo-able and legible on stage.
- **Rehearse the live demo 5+ times and record a backup video**, per your own checklist — keep this, it's the right call.
- **Rename components for the pitch** (Risk Scoring & Policy Engine / Security Correlation Engine / Post-Quantum Readiness Analyzer / AI Threat Prioritization Model) — cosmetic, cheap, and makes the architecture diagram read like an enterprise product instead of a hackathon script.
- **Add the analyst feedback loop (✓ True Threat / ✗ False Positive), store-only, no retraining required.** Cheap to build, and "the model improves from analyst feedback" is a sentence judges remember.

## 4. DO NOT

- **Do not build a GNN.** Correctly ruled out already — high complexity, low demo value, real risk of not finishing. Leave it out entirely, don't even mention it as a "future roadmap" unless a judge asks.
- **Do not invest real engineering time in the RBAC/admin-vs-analyst login screen.** That's a PS1 (Privileged Access Management) concept, not PS2. A mock login exists to *look* secure for 10 seconds of demo — one static screen, zero backend logic. If you're writing real auth middleware, you're spending PS1 time on a PS2 submission.
- **Do not let the Quantum Module stay a standalone tab.** As-is, it reads as scope-padding ("we also did quantum!") rather than correlation. A disconnected feature is worse for your score than no feature — it invites the judge question "how does this correlate with anything?" and you won't have a good answer unless you fuse it per Section 3.
- **Do not run the live demo across two laptops over local network** unless you've tested that handoff repeatedly and it's rock solid. Network demos fail in front of judges more often than almost anything else. Default to one machine; only split if thermal throttling is empirically a real problem, and test the split at least 3 times before demo day.
- **Do not spend time on git branching strategy, PR review requirements, or issue-tracking ceremony.** None of it is judged. A working `main` branch and clean commit history is enough.
- **Do not write comprehensive unit tests.** Your instinct to skip this for a 5-day build is correct — stick to integration + model sanity + LLM stability checks only, as you already planned.
- **Do not over-polish CSS/theme beyond dark-mode + accent colors.** Streamlit defaults are fine. Time spent here doesn't move the score; time spent on the correlation-to-quantum fusion does.
- **Do not present XGBoost/SHAP/Ollama as the headline.** They're implementation detail. The headline is "we correlate telemetry and transactions to kill false positives, and we explain every decision." Judges score the capability, not the library names — mention the stack once, move on.

---

## 5. Data Fusion Logic — BankSim + CICIDS2017 → Correlated Incidents

**The core problem:** BankSim gives you realistic transactions (customer_id, merchant, amount, timestamp/"step"). CICIDS2017 gives you real attack flows (source_ip, dest_ip, timestamp, duration, protocol, label). Neither dataset knows the other exists — there's no shared customer ID, no shared IP space, no shared clock. You have to build that link. That link *is* your product.

**Files in use (from the earlier extraction decision):**
- `Tuesday-WorkingHours.pcap_ISCX.csv` → SSH/FTP-Patator brute force (credential theft archetype)
- `Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv` → Web Attack: Brute Force / XSS / SQLi (app-compromise archetype)
- `Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv` → Port Scan (recon-only, telemetry-first archetype)

### Step 1 — Identity Fabric (build once, offline)
For every synthetic customer in BankSim, generate a small identity record:
```
customer_id → {
  home_ip: <fake but consistent IP>,
  device_ids: [primary_device, occasional_mobile],
  risk_pool: bool   # true for the subset of customers who will host injected incidents
}
```
Only a minority of customers (say 10–15%) get `risk_pool = true` — these are the ones incidents get attached to. Everyone else's BankSim transactions flow through untouched, which is what creates real background noise for your false-positive-reduction story (Section 3).

### Step 2 — Incident Injection (build once, offline, produces your demo dataset)
For each `risk_pool` customer you want to turn into an incident:
1. Pick an archetype (credential theft / app compromise / recon-only) and sample one matching row from the corresponding CICIDS file.
2. **Remap identity**: replace the CICIDS row's `Source IP` with the customer's `home_ip` (keep the original CICIDS IP in a hidden `raw_source_ip` field for lineage/defensibility if a judge asks).
3. **Remap time**: pick (or use) a BankSim transaction timestamp for this customer as the anchor `T`. Compute `attack_end = T - random(2, 15 minutes)`, `attack_start = attack_end - flow_duration` (flow_duration comes straight from the CICIDS row, so the *relative* timing of the attack stays real even though the absolute placement is synthetic).
4. Tag both the resulting telemetry event and the BankSim transaction with a shared `incident_id` and `customer_id`.
5. **Recon-only exception**: for port-scan-archetype incidents, don't attach a transaction at all (or attach one much later, e.g. +1–3 days) — this is your telemetry-first, no-transaction-yet alert, which is exactly what closes the "proactive detection" gap from Section 2.

### Step 3 — Session Reconstruction (runtime, this is what the judges see)
Given an `incident_id`, pull every tagged event (telemetry + transaction), sort by timestamp, and render as a single timeline:
```
09:01  Login (home_ip)
09:03  SSH brute-force detected (raw CICIDS signature, remapped IP)
09:05  VPN / new-IP session
09:08  New device fingerprint
09:10  ₹85,000 transfer initiated        ← BankSim transaction
09:12  Session ends
```
This is the artifact that goes into the SHAP/LLM explanation step — the model isn't scoring a lone transaction, it's scoring this whole reconstructed session.

### Step 4 — What to say if a judge asks "is this correlation real?"
Be direct, not defensive: *"The transaction behavior is drawn from BankSim's real fraud-simulation distributions, and the attack signatures are real CICIDS2017 intrusion traces. The linkage between a specific attack and a specific transaction is a synthetic mapping we built — because no public dataset pairs the two — but the relative timing, durations, and signal shapes inside that mapping are all drawn from real data, not invented."* That answer is accurate and it's a stronger claim than "we made up some data," without overclaiming realism you can't defend.

### Practical build notes
- Precompute a fixed set of ~15–20 injected incidents for demo determinism (never rely on random generation live on stage), plus optionally a "generate new incident" button for interactivity/wow-factor if time allows.
- Strip leading whitespace from CICIDS column headers before anything else (`' Flow Duration'` vs `'Flow Duration'`) — this silently breaks joins otherwise.
- Keep only the ~6 CICIDS columns you actually need (Source IP, Dest IP, Timestamp, Flow Duration, Protocol, Label) — don't drag all ~78 statistical columns into your feature set, they add noise without adding to the correlation story.

---

## 6. Priority order for the next 5 days

**P0 — must work, everything else is worthless without these:**
1. BankSim + CICIDS2017 identity fabric and incident injection pipeline (Section 5), producing correlated attack-graphs — not pure synthetic generation
2. Risk Engine → Orchestrator → Telemetry Correlator → XGBoost pipeline, end to end
3. SHAP explanation rendering in the UI
4. LLM summary generation, non-blocking, under 5s

**P1 — what separates a working demo from a winning one:**
5. Quantum-signal fusion into the composite threat score (Section 3)
6. Telemetry-triggered (proactive) detection path, even a simplified version
7. False-positive reduction stat surfaced prominently on the dashboard
8. Analyst feedback buttons (store-only)

**P2 — nice-to-have, only if P0/P1 are done and stable with a day to spare:**
9. Mock login screen
10. Component renaming across diagrams/UI copy
11. Extra dashboard charts / migration table polish

If you're behind schedule on Day 4, cut from P2 first, then trim P1's scope (e.g., quantum fusion can be a single hardcoded bump rather than a tuned weight) — never cut P0.

---

## 7. Questions judges will likely ask — have answers ready

- **"How does the quantum module actually relate to the correlation engine?"** — Have the fused-score answer from Section 3 ready. If you haven't built the fusion, don't claim it — say clearly what's simulated vs. live.
- **"What happens if the LLM hallucinates a wrong summary?"** — Point to the system prompt's "do not hallucinate data" constraint and the fact that SHAP values are ground-truth and displayed independently of the LLM text, so the analyst never relies on the LLM alone.
- **"Why XGBoost and not a deep model?"** — Tabular data, small dataset, need for SHAP-based explainability, and inference speed for real-time correlation. This is a *correct* engineering answer, say it plainly.
- **"Is this trained on real bank data?"** — No — BankSim (a research-grade agent-based financial simulator calibrated on aggregated real banking behavior) for transactions, CICIDS2017 (a real intrusion-detection benchmark) for attack signatures. The linkage between a specific attack and a specific transaction is synthetic — see Section 5, Step 4 for the exact phrasing — because no real bank will hand over paired transaction/telemetry data for a hackathon. The architecture is what's being evaluated, not the specific trained weights.
- **"How would this scale beyond SQLite?"** — One sentence: SQLite is the 5-day event store; production would swap in a time-series/event-streaming backend (e.g. Kafka + a proper OLAP store) without changing the correlation logic. Don't over-elaborate, this isn't the focus area.

---

## 8. Demo script — tightened

Keep your existing 4-person structure, but make sure two lines land explicitly because they map directly to rubric language:

- Someone must say the words **"correlates cybersecurity telemetry with transactional behaviour"** or a close paraphrase, out loud, early.
- Someone must say a **concrete false-positive-reduction number**.
- Someone must show the **quantum signal contributing to a score**, not just sitting in its own tab.
- Someone must say **"explainable"** while pointing at the SHAP chart, not just show the chart silently.

Everything else in your existing script (the 47-of-50-filtered beat, the SHAP/LLM investigation view, the HNDL closing line) is already strong — don't rewrite it, just make sure the four beats above are explicit.
