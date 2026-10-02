# rmule-primitives Fixtures

Fixtures are compatibility evidence for protocol primitives.

- `links/`: TOML cases for ED2K link parsing and canonical formatting.
- `packets/`: paired binary and TOML packet fixtures.

Every non-placeholder fixture must record provenance:

- `handwritten`
- `documentation`
- `amule-generated`
- `captured`

Use synthetic names, hashes, hosts, and packets unless a real capture is necessary and safe to store.
