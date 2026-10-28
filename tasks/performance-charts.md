# Performance chart views

- [x] Inspect current scoring, labels and scan-list contracts.
- [x] Extend the existing chart with scanner/type grouping and optional label splits.
- [x] Add precision/recall, paired weighting shifts and accessible cost colors.
- [x] Verify calculation edge cases, production build and browser interactions at desktop and narrow widths.
- [x] Capture synthetic-data screenshots and prepare a draft PR.

## Contracts

- Scanner and recorded scan type are independent; model and harness variations use labels.
- Group by scanner/type, with optional selected-label membership splits. Do not guess models.
- Average valid contributing runs equally. Precision/recall retains runs without accessible cost;
  group cost is unavailable if any included run lacks it.
- Shift endpoints use the same reviewed paired cohort. Weighted recall uses canonical impact
  coverage including chains, rather than a new severity-count metric.
- Preserve URL state through `chart_plot`, `chart_group`, `chart_weight` and repeated `chart_label`.

## Review

- Nine chart utility tests pass, including grouping, missing costs and paired-shift cohorts.
- All 24 frontend tests and production build pass; browser verification covers grouping,
  searched variation selection, chips, both chart views, weighting, duration, and missing costs.
- Screenshots use synthetic local fixtures, including RIFT whitebox and unknown-cost groups.
- Revised the variation UX after feedback: searchable picker, removable chips and compact
  names replace checkbox lists and repeated negative-label names.
- Draft PR targets upstream main; screenshot previews contain synthetic data only.
