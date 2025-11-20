# Project 3 Architecture Overview

This document explains how the Project 3 refactor extends the earlier virus
scanner hook libraries with richer object-oriented design.

## Inheritance Hierarchies

```
ScanArtifact (ABC)
├── SourceCodeArtifact
├── BinaryArtifact
└── ManifestArtifact

AbstractScanStrategy (ABC)
├── HashLookupStrategy
├── ChunkedUploadStrategy
└── ManifestInsightStrategy

HookBase (ABC)
├── PrePushHook
└── ManualScanHook
```

- `ScanArtifact` unifies metadata collection for any staged asset. Each subclass
  overrides `_specialized_metadata()` and `preferred_strategy()` to describe its
  own domain rules (text source, binaries, dependency manifests). The hierarchy
  keeps shared behaviors (path handling, hashing, binary detection) in one place.
- `AbstractScanStrategy` encapsulates “how to talk to the scanner”. Derived
  strategies override `_submit()` but the base class owns the workflow for
  assembling metadata and normalizing responses. This is a classic Strategy
  pattern layered atop inheritance.
- `HookBase` defines a push/scan template method. `ManualScanHook` overrides
  `run()` and calls `super().run()` to add extra logging while `PrePushHook`
  simply supplies staged artifacts.

## Abstract Base Classes & Polymorphism

- Both `ScanArtifact` and `AbstractScanStrategy` use Python’s `abc` module to
  enforce required overrides. Attempting to instantiate either directly raises
  `TypeError`, which the new tests assert.
- Polymorphism is demonstrated when `ScanSession.scan_artifacts()` receives a
  heterogenous list of `ScanArtifact` objects (source, binary, manifest) yet
  treats them uniformly. It resolves the correct `AbstractScanStrategy` through
  `ScanStrategyRegistry` and calls `strategy.scan(artifact)` without knowing the
  concrete type. Each strategy talks to the API differently (chunked uploads
  vs. hash lookups vs. manifest annotation), but the orchestrator code never
  branches on type checks.
- Hooks exhibit polymorphism as well: the caller depends on the `HookBase`
  interface, while `ManualScanHook` and `PrePushHook` customize behavior.

## Composition Decisions

- `ScanSession` *has-a* `ArtifactFactory`, `ScanStrategyRegistry`, API client,
  and configuration. Composition keeps responsibilities separate: factories
  decide types, strategies handle submissions, and the session coordinates them.
- Hooks compose a `ScanSession` to reuse the scanning pipeline rather than
  inherit from it. Hooks change “where do artifacts come from?” without touching
  networking code—another deliberate composition choice.

## Design Patterns & Rationale

- **Strategy Pattern:** `AbstractScanStrategy` and its implementations model how
  to scan different artifacts. This keeps policy and mechanics de-coupled.
- **Template Method Pattern:** `HookBase.run()` defines the skeleton of the
  workflow (collect → scan → report → evaluate). Subclasses plug in collection
  logic or augment behavior via `super()`.
- **Factory Pattern:** `ArtifactFactory` centralizes how file metadata maps to
  artifact classes. Adding a new artifact type only requires extending the
  factory, leaving scanning logic untouched.

## Why Composition over Inheritance?

- `ScanSession` owns resources (config, client, artifact factory). Letting
  `HookBase` inherit from `ScanSession` would expose too much API surface and
  tightly couple concerns. Composition lets hooks swap sessions (e.g., mocked
  sessions for tests) and keeps dependencies explicit.
- `ManualScanHook` composes an `ArtifactFactory` instance to build artifacts
  dynamically from manual paths. Inheriting from `ArtifactFactory` would not
  make sense because a hook is not a specialized factory; it merely *uses* one.

## Polymorphism in Practice

Example snippet from `ScanSession.scan_artifacts()`:

```python
for artifact in artifacts:
    strategy = self._strategies.for_artifact(artifact)
    results[artifact.relative_path] = strategy.scan(artifact)
```

The same method call (`strategy.scan`) produces different behavior depending on
whether the artifact is a binary (chunked uploads), source code (hash lookup),
or manifest (dependency-aware scan) while remaining type-agnostic.

## Summary

Project 3 elevates the previous procedural / flat-class approach into a layered,
extensible architecture. Inheritance provides reusable contracts, polymorphism
keeps the orchestrator generic, and composition cleanly wires independent
components together for flexibility and testability.

