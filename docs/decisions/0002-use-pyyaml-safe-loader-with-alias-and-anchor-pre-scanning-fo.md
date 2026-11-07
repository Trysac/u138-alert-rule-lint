# Use PyYAML safe loader with alias and anchor pre-scanning for Prometheus rule verification

Status: accepted (generated, pending human review)

## Context

The standard library does not provide a YAML parser, and Prometheus rule files are authored in YAML. However, YAML parsers can be vulnerable to arbitrary code execution if full loaders are used, or denial of service via recursive anchor/alias expansion (Billion Laughs style).

## Decision

Use PyYAML (>=6.0,<7) restricted strictly to `SafeLoader` and `safe_load_all`. Prior to loading the document object graph, use `yaml.scan` with `SafeLoader` to scan tokens and immediately reject any `AnchorToken` or `AliasToken` with code `aliases_not_allowed`. Additionally, enforce an iterative tree depth check with limit 20 and an input size limit of 5 MiB.

## Consequences

Malicious or circular YAML inputs cannot trigger parser denial-of-service, memory exhaustion, or code injection. Prometheus rules are reliably checked for structural and team policy compliance.
