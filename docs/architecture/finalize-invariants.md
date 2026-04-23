# Finalize and Publish Invariants

## Publish Contract

A store path becomes visible to Nix clients only after all three conditions hold:

1. The compressed NAR blob exists in R2 at a content-addressed key.
2. The upload session status is "completed" (R2 object verified).
3. The published_paths row is committed in D1.

## Idempotency

The publish handler checks for an existing published_paths row before
inserting. If the path is already published, it returns the existing
result with `alreadyExisted: true`. This makes retries safe.

The UNIQUE(cache_id, store_path_hash) constraint in D1 provides a
database-level backstop against concurrent duplicate inserts. If two
concurrent publish requests race past the check, one will succeed and
the other catches the constraint violation and falls back to returning
the existing row with `alreadyExisted: true`.

The same pattern applies to blob_objects: a UNIQUE(file_hash, compression)
constraint prevents duplicates, and the handler catches violations to
look up the existing blob.

## Content-Addressed Dedup

Blob objects are keyed by (file_hash, compression) with a unique constraint.
When two different store paths produce the same compressed output, they
share the same blob_objects row and R2 key.

The publish handler looks up an existing blob_objects row before creating
one. If a blob with matching file_hash and compression already exists, it
reuses it rather than creating a duplicate.

## Upload Session Lifecycle

```
pending → uploading → completed → (publish) → path visible
    ↘                     ↗
     expired (via GC)
```

- Only "completed" sessions can be published.
- Sessions expire after 1 hour if not completed.
- The GC cron cleans up expired sessions and their R2 artifacts.

## Retry Safety

| Operation | Retry behavior |
|-----------|---------------|
| Create session | New session each time (no dedup) |
| Complete upload | Returns 409 if already completed |
| Publish | Returns existing result if already published |
| Get missing paths | Stateless, always safe |
