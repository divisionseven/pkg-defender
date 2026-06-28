# Scoring Formula

The final threat score combines four factors:

```
final_score = severity_score × source_confidence × corroboration_multiplier × recency_decay
```

The result is clamped to a maximum of 1.0.

## Severity Base Scores

| Severity | Base Score |
| -------- | ---------- |
| CRITICAL | 1.0        |
| HIGH     | 0.8        |
| MEDIUM   | 0.5        |
| LOW      | 0.3        |
| UNKNOWN  | 0.1        |

## Source Confidence Weights

Each intelligence source has a confidence weight reflecting its reliability:

| Source (Display Name)  | Code Identifier  | Confidence | Rationale                                   |
| ---------------------- | ---------------- | ---------- | ------------------------------------------- |
| OpenSSF Malicious Pkgs | `ossf_malicious` | 1.0        | Authoritative malicious package list        |
| Socket.dev             | `socket`         | 0.95       | Real-time, most accurate for active attacks |
| OSV.dev                | `osv`            | 0.90       | Structured, version-precise, curated        |
| Homebrew OSV           | `homebrew_osv`   | 0.90       | Homebrew OSV — same upstream OSV DB as osv  |
| GHSA                   | `ghsa`           | 0.85       | High quality but bulk/advisory-level        |
| npm Advisory           | `npm_advisory`   | 0.80       | npm registry advisories                     |
| X/Twitter              | `x_twitter`      | 0.50 ⑴     | BYOK, varies by trusted account             |
| RSS                    | `rss`            | 0.50       | Unstructured text, keyword matching         |
| Reddit                 | `reddit`         | 0.45 ⑴     | Social but moderated communities            |
| Mastodon               | `mastodon`       | 0.40 ⑴     | Social, noisy, high false positive          |

> `⑴` Effective confidence capped at `min(confidence, 0.2)` at runtime — see `scorer.py:126-128`. This ensures social feeds remain informational-only and cannot produce blocking scores (BLOCK_SCORE_THRESHOLD = 0.3).

Unknown sources default to 0.5 confidence.

**Code identifiers:** The "Code Identifier" column shows the string used in the codebase (see `src/pkg_defender/core/scorer.py`). Display names are for human readability; code identifiers are used in the implementation.

## Multi-Source Corroboration

When multiple independent sources confirm the same threat, a bonus multiplier is applied:

| Sources Confirming | Multiplier | Effect          |
| ------------------ | ---------- | --------------- |
| 1                  | 1.0x       | No boost        |
| 2                  | 1.15x      | 15% boost       |
| 3                  | 1.25x      | 25% boost       |
| 4+                 | 1.30x      | 30% boost (cap) |

## Recency Decay

Threats lose relevance over time. The score decays by 5% per week:

```
decay = max(0.5, 1.0 - weeks_old × 0.05)
```

- **Minimum decay:** 50% of original score (threats never fully expire)
- **Decay rate:** 5% per week
- **Age basis:** Calculated from `first_seen` timestamp

## Display Severity Mapping

The numeric score maps back to a human-readable severity:

| Score Range | Display Severity |
| ----------- | ---------------- |
| ≥ 0.9       | CRITICAL         |
| ≥ 0.7       | HIGH             |
| ≥ 0.4       | MEDIUM           |
| > 0.0       | LOW              |
| 0.0         | UNKNOWN          |

## Limitations and Known Caveats

### Empirical Validation Status

The scoring model is **heuristic, not empirically validated**. All parameter
values in this document are developer-assigned defaults based on design
reasoning, not measured false positive/negative rates. No controlled testing
has been performed to determine optimal weights or thresholds.

### All Parameters Are Arbitrary Defaults

Every numeric value in the scoring formula is a design-time default that has
not been tuned against real-world threat data:

| Parameter                    | Current Value | How Determined                       | Validated? |
| ---------------------------- | ------------- | ------------------------------------ | ---------- |
| CRITICAL severity score      | 1.0           | Design choice (maximum)              | No         |
| HIGH severity score          | 0.8           | Design choice                        | No         |
| MEDIUM severity score        | 0.5           | Design choice (midpoint)             | No         |
| LOW severity score           | 0.3           | Design choice                        | No         |
| UNKNOWN severity score       | 0.1           | Design choice (near-zero)            | No         |
| OpenSSF confidence           | 1.0           | Authoritative source assumption      | No         |
| Socket.dev confidence        | 0.95          | High trust assumption                | No         |
| OSV confidence               | 0.90          | Structured data assumption           | No         |
| GHSA confidence              | 0.85          | Advisory-level assumption            | No         |
| Social feed cap              | 0.2           | Safety floor for blocking prevention | No         |
| Corroboration 2-source boost | 1.15x         | Design choice                        | No         |
| Corroboration 3-source boost | 1.25x         | Design choice                        | No         |
| Corroboration 4+-source cap  | 1.30x         | Design choice                        | No         |
| Recency decay rate           | 5%/week       | Design choice                        | No         |
| Recency floor                | 50%           | Design choice                        | No         |
| Block threshold              | 0.3           | Safety boundary for social feeds     | No         |
| Unknown source default       | 0.5           | Neutral assumption                   | No         |

### What Scores Mean

- **Scores are relative rankings, not probabilities.** A score of 0.8 does
  *not* mean "80% chance this is a real threat." It means this threat ranked
  higher than others in the current evaluation.
- **Scores are not comparable across packages.** The same score for different
  packages does not imply equivalent risk — it reflects the relative threat
  signal within each package's evaluation context.
- **Score magnitude is not interpretable.** The difference between 0.5 and 0.6
  is not meaningful in absolute terms. Only the ranking order matters.

### What the Model Does Well (by Design)

- **Social feeds cannot block installs.** The `min(confidence, 0.2)` cap on
  social sources (`scorer.py:126-128`) combined with the `BLOCK_SCORE_THRESHOLD
  = 0.3` guarantee makes this structurally impossible.
- **Multi-source corroboration increases confidence.** Independent confirmation
  from multiple sources is a reliable signal, even without empirical tuning.
- **Recency decay prevents stale threats from dominating.** Older threats
  naturally fade in relevance.
- **Fail-closed defaults.** Unknown sources, unknown severities, and edge cases
  all produce non-zero scores that err toward caution.

### Future Improvements Needed

- Empirical testing with labeled threat data to validate or adjust weights
- False positive/negative rate measurement across severity tiers
- Threshold tuning based on real-world blocking decisions
- Per-ecosystem weight adjustments based on observed data quality
- A/B testing framework for parameter sensitivity analysis
