# Scoring

Why the threat scoring system works the way it does — the reasoning behind the thresholds, weights, and design choices.

## Block Score Threshold

`BLOCK_SCORE_THRESHOLD = 0.3` is the boundary below which a threat cannot block an install. This threshold serves as a critical safety mechanism: **social feeds can never block installs on their own.**

### Why Social Feeds Cannot Block

The threshold is set at 0.3 because social intelligence sources have a code-enforced confidence cap (`min(source_conf, 0.2)`, see `scorer.py:126-128`). Even with CRITICAL severity and maximum corroboration, a social feed cannot reach the threshold without a higher-confidence structured source.

**The ceiling calculation:** A CRITICAL severity (1.0) reported by Mastodon (confidence capped at 0.2):

```
1.0 × 0.2 = 0.20
```

This is below 0.3 — the cap alone guarantees social feeds cannot block, even with the highest possible inputs. Social feeds are also never assigned CRITICAL or HIGH severity in practice. Their reports are classified as LOW severity (0.3) due to the unstructured, unverifiable nature of social intelligence, but the cap is the primary guarantee.

**The realistic calculation:** LOW severity (0.3) reported by Mastodon (confidence capped at 0.2):

```
0.3 × 0.2 = 0.06
```

Even with maximum corroboration (4+ sources, 1.3x multiplier) and no decay:

```
0.06 × 1.3 = 0.078
```

This is well below 0.3. Social intelligence can inform a threat assessment but can never trigger a block on its own. A block requires either:

- A high-confidence structured source (OSV, Socket, GHSA) reporting at least a MEDIUM severity threat.
- Multiple structured sources corroborating a MEDIUM or higher threat.

This design ensures that noisy or unverifiable social feeds contribute signal without being able to cause a denial of service.

## Example Scenarios

### Scenario 1: OSV (osv) CRITICAL vulnerability

A CRITICAL severity vulnerability published in the OSV database, confirmed by a single source and reported one week after disclosure.

```
severity: CRITICAL (1.0)
source: osv (0.9)
corroboration: 1 source (1.0x)
recency: 1 week old (0.95)

score = 1.0 × 0.9 × 1.0 × 0.95 = 0.855
display: HIGH
```

Even though the raw severity is CRITICAL, the recency decay (5% loss for one week of age) and the 0.9 confidence of OSV bring the final score to 0.855 — which maps to a HIGH display severity. This means the threat is taken seriously but the single-source confirmation + slight age prevent it from reaching the CRITICAL display tier.

### Scenario 2: Socket (socket) multi-source corroboration

A HIGH severity vulnerability reported by Socket.dev, independently confirmed by two other sources, with no age decay.

```
severity: HIGH (0.8)
source: socket (0.95)
corroboration: 3 sources (1.25x)
recency: fresh (1.0)

score = 0.8 × 0.95 × 1.25 × 1.0 = 0.95
display: CRITICAL
```

Despite starting at HIGH severity, the multi-source corroboration (three independent confirmations) and the high confidence of Socket.dev push the final score to 0.95 — crossing into the CRITICAL display tier. This demonstrates how corroboration can elevate a threat's perceived severity when multiple trusted sources agree.

### Scenario 3: Mastodon (mastodon) social feed report

A LOW severity report from Mastodon, corroborated by one other social source, with no age decay.

```
severity: LOW (0.3)
source: mastodon (capped at 0.2)
corroboration: 2 sources (1.15x)
recency: fresh (1.0)

score = 0.3 × 0.2 × 1.15 × 1.0 = 0.069
display: LOW (below BLOCK_SCORE_THRESHOLD)
```

This scenario shows why social feeds cannot block installs. Even with two sources corroborating and no age penalty, the score reaches only 0.069 — well below the 0.3 block threshold. The threat is recorded and visible but can never trigger a block action.

## Transparency: Model Validation Status

### Honest Disclosure

This section exists to ensure users understand the confidence level they should
place in scoring outputs. The scoring model is a **heuristic system** — its
parameters were chosen based on design reasoning, not empirical measurement.

### What Has Been Validated

- **Structural guarantees are verified.** The social-feed blocking prevention
  (cap + threshold) is mathematically proven and tested. No social feed source
  can produce a blocking score — this is a structural property, not an
  empirical claim.
- **Score ordering is directionally correct.** Higher-confidence sources
  produce higher scores for the same severity. Multi-source corroboration
  elevates scores. Older threats decay. These are design invariants that hold
  regardless of specific parameter values.

### What Has NOT Been Validated

- **Specific weight values.** The difference between 0.85 (GHSA) and 0.90
  (OSV) has not been measured against real data. These are informed guesses.
- **Severity-to-score mappings.** Whether CRITICAL=1.0, HIGH=0.8, MEDIUM=0.5
  reflects actual severity distributions is untested.
- **Corroboration multipliers.** The 15%/25%/30% boosts are design choices,
  not empirically derived.
- **Decay rate.** The 5%-per-week decay has not been calibrated against actual
  threat lifecycle data.
- **Block threshold.** The 0.3 threshold was set to exclude social feeds, not
  to optimize false positive/negative tradeoffs.

### Practical Implications

- **Do not use scores for risk quantification.** Scores indicate relative
  threat ranking within a single evaluation, not absolute risk levels.
- **Do not compare scores across different contexts.** The same score for
  different packages or ecosystems does not imply equivalent risk.
- **Treat thresholds as configurable, not optimal.** The block threshold and
  severity mappings may need adjustment as real-world data accumulates.
- **Report false positives and negatives.** User feedback on blocking decisions
  is the primary mechanism for improving the model over time.
