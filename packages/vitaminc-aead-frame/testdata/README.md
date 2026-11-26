# Storage profile corpus

`storage-v1.json` is the golden corpus for version 1 of the storage profile
(`STORAGE.md`). Its rows are never edited or removed; new rows may be added.
`scripts/storage_corpus_append_only.py` checks that.

The file is Biome-formatted. The formatter may change its layout, never its
parsed content. The Rust tests and the append-only check parse it as JSON,
so the layout fails neither. After adding a row, run `pnpm run code:fix`
before committing.
