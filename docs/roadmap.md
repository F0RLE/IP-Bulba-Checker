# Roadmap

---

## Current Focus — v0.1.4 Practical Productization

> Primary goal: reduce operator friction, make outputs easier to consume, and turn the current scanner into a cleaner repeatable workflow.

## Active Priorities

- **Output surface reduction**
  - Usefulness: 8/10
  - Status: in progress
  - What it gives: fewer default artifacts, less duplication, and a smaller operator-facing result surface.
  - Remaining:
    - decide which source and binary exports should coexist by default
    - move advanced export families behind clearer profile or flag boundaries
    - remove or hide compatibility outputs that are not part of the main operator path

- **Known-dataset benchmarking**
  - Usefulness: 8/10
  - Status: in progress
  - What it gives: a stable way to compare classification quality between versions instead of relying only on ad hoc scans.
  - Remaining:
    - define small representative benchmark datasets
    - record expected classification outcomes for regression testing
    - add repeatable quality checks for accuracy-sensitive changes

- **State lifecycle cleanup**
  - Usefulness: 7/10
  - Status: in progress
  - What it gives: less stale cache buildup and clearer long-term scan state behavior.
  - Remaining:
    - define retention and cleanup rules for state and queue files
    - separate long-lived state from per-run artifacts more explicitly
    - document safe cleanup paths for operators

- **Preset-based export modes**
  - Usefulness: 7/10
  - Status: in progress
  - What it gives: clearer ready-to-use outputs for `sing-box`, `mihomo`, `OpenWrt`, and generic review workflows.
  - Remaining:
    - define opinionated presets for the main consumer ecosystems
    - make the default export profile easier to understand without reading all docs
    - document which preset maps to which deployment style

- **Feed packaging and distribution**
  - Usefulness: 7/10
  - Status: in progress
  - What it gives: a cleaner path from local scans to reusable update bundles and published artifacts.
  - Remaining:
    - define feed bundle structure and metadata
    - define versioning for publishable outputs
    - separate operator-local results from distributable feed artifacts

- **Release validation matrix**
  - Usefulness: 7/10
  - Status: in progress
  - What it gives: more reliable releases across profiles, platforms, and common operator setups.
  - Remaining:
    - add smoke validation for `safe` and `aggressive` flows
    - validate common export paths and generated artifacts
    - make release confidence less dependent on manual spot checks

---

## Completed in v0.1.3

> v0.1.3 delivered the core selective-proxy classification pipeline and the first practical operator workflow.
>
> Full release summary: [releases/v0.1.3.md](releases/v0.1.3.md)

- **Core accuracy**
  - DNS-level block detection
  - dual-vantage confidence cleanup
  - browser confirmation as a bounded secondary layer
  - broader service-profile coverage

- **Performance and scale**
  - concurrent domain ingestion
  - moving average ETA smoothing

- **Exports and operator workflow**
  - direct `.srs` and Mihomo `.mrs` generation
  - global `bulbascan.toml` configuration
  - enhanced scan reports and publication guidance
  - incremental publishing workflow
  - cross-platform runtime hardening
  - output layout simplification

---

## Parking Lot

> These ideas are intentionally not part of the active roadmap. They are either research-heavy, low-ROI, or only useful after a future product shift.

- **ECH (Encrypted Client Hello) Support**
  - Usefulness: 4/10
  - Why parked: useful as a research signal, but not a strong immediate product win for the current classification pipeline.

- **XHTTP & HTTP/3 Probing**
  - Usefulness: 4/10
  - Why parked: transport-research heavy and only worth reviving if real ambiguous cases clearly demand it.

- **Daemon / REST API Mode**
  - Usefulness: 4/10
  - Why parked: only makes sense after the current operator workflow hardens into a stable service contract.

- **AI Labyrinth / visibility-safe interaction**
  - Usefulness: 3/10
  - Why parked: unnecessary unless browser confirmation becomes materially more interactive than it is today.
