# Project record

## Objective

Lint Prometheus alerting and recording rule files for structural compliance and team-defined policies (required labels, annotations, naming, and key validation).

## Scope

- Enforcement of organizational policies defined in `LintConfig`.
- Structural validation of rule files.
- Safe, non-deserializing YAML validation.

## Out-of-scope

- PromQL parsing or validation.
- Recording rule naming convention enforcement.
- Alertmanager routing configuration.
- Auto-fixing of rule files.

## Effort metrics

| Metric | Value |
|---|---|
| Tokens (input / output) | 2498684 / 19194 |
| Hours (human) | pending measurement |
| Cost (USD) | 0.5066 |

## Factory run u138 (measured from API usage)

| Phase | Model | Batch | Input | Output | Cache write | Cache read | Cost (USD) |
|---|---|---|---|---|---|---|---|
| generation | gemini-3.8-flash | yes | 4108 | 11012 | 0 | 0 | 0.0222 |
| fix-1 | gemini-3.8-flash | no | 78299 | 2701 | 0 | 353576 | 0.0954 |
| fix-2 | gemini-3.8-flash | no | 87805 | 1116 | 0 | 605572 | 0.1155 |
| fix-3 | gemini-3.8-flash | no | 115436 | 808 | 0 | 524288 | 0.1289 |
| fix-4 | gemini-3.8-flash | no | 73390 | 1751 | 0 | 478498 | 0.0975 |
| docs | gemini-3.1-flash-lite | no | 177712 | 1806 | 0 | 0 | 0.0471 |

Total: $0.5066. Prices: Anthropic list prices.
