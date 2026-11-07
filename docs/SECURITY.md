# Security notes

## Threat model

`alert-rule-lint` is a library. Security focuses on preventing DoS during YAML processing and ensuring input does not contain malicious payloads.

## Defended limits

- **Anchor/Alias Injection**: The linter uses `yaml.scan` with `yaml.SafeLoader` to reject `AnchorToken` and `AliasToken` before parsing, effectively stopping YAML billion-laughs attacks.
- **Depth Limits**: The library performs iterative depth checks on the loaded YAML, limiting nested structures to a depth of 20 (`too_deep`).
- **Memory Exhaustion**: Inputs are capped at 5 MiB (5,242,880 bytes). Error messages are truncated to 200 characters.
- **Arbitrary Code Execution**: `yaml.safe_load_all` is used exclusively. No unsafe loaders are accessible to the user.

## Not defended

- The library does not sanitize output messages for downstream systems (e.g., terminal output or web UI). It assumes the calling application performs necessary output encoding.