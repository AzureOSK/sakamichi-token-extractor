# Maintenance and failure-analysis guide

This document is a handoff for future maintainers and LLM-assisted debugging. It records the current known-good behavior, the extractor's assumptions, safe evidence to collect, and how to isolate failures after an iOS or app update.

## Security boundary

Never provide any of the following to an issue tracker, an LLM, CI, or another person:

- a refresh or access token;
- the encrypted-backup password;
- a complete iPhone backup;
- `keychain-backup.plist` or decrypted Keychain records;
- raw `v_Data` values;
- decrypted `Manifest.db` contents;
- an unredacted device identifier or backup path.

`diagnostics.json` is deliberately metadata-only and is the preferred debugging artifact. `index.json` contains no token values, but its absolute output paths can expose a local username or directory layout; redact those paths before sharing it. Console output can similarly contain a device name and local paths.

Do not add a debug mode that dumps every Keychain value. New diagnostics should report types, counts, versions, field names, lengths, classifications, and redacted identifiers—not secrets.

## Current known-good baseline

The following was observed on 2026-09-01:

- Tool release used for the live extraction: `v0.1.4` on macOS ARM64.
- `v0.1.5` changed output placement and documentation; it did not change backup, Keychain, matching, or token parsing logic.
- Source device: iOS 26.6.
- Source: a fresh encrypted Finder-style local backup.
- Result: one distinct token recovered for each of Nogizaka46, Sakurazaka46, and Hinatazaka46.
- App versions were not recorded. Future known-good reports should always record all three app versions.

Known-good diagnostics:

```json
{
  "general_entries": 5553,
  "record_versions": {
    "3": 5553
  },
  "decrypted_records": 3791,
  "decrypt_failures": {
    "no backup class key for class 9": 149,
    "no backup class key for class 10": 1017,
    "no backup class key for class 11": 596
  },
  "default_service_count": 60,
  "target_account_count": 0,
  "refresh_token_json_count": 5
}
```

The missing class keys above were present during a successful extraction. Their presence alone is not evidence of a regression. The 1,762 failures plus 3,791 decrypted records account for all 5,553 generic-password entries.

The three successful candidate identifiers were:

| App | Service | Account | Access-group suffix |
|---|---|---|---|
| Nogizaka46 | `flutter_secure_storage_service` | `TOKEN_KEY` | `jp.co.sonymusic.communication.nogizaka` |
| Sakurazaka46 | `flutter_secure_storage_service` | `TOKEN_KEY` | `jp.co.sonymusic.communication.sakurazaka` |
| Hinatazaka46 | `flutter_secure_storage_service` | `TOKEN_KEY` | `jp.co.sonymusic.communication.keyakizaka` |

An Apple team identifier precedes each access-group suffix and is intentionally omitted here. Hinatazaka still uses the historical `keyakizaka` bundle identifier.

Important baseline observations:

- The current account is `TOKEN_KEY`, not `FC_TOKEN_KEY_...`.
- `target_account_count` was therefore zero during a completely successful run.
- Current records match through the Flutter service plus the recognized access group.
- Five decrypted JSON values contained a refresh-token field, but only three distinct target tokens were written. Duplicates or other matching JSON records are not automatically a failure.
- The observed token length was 36 characters. Length is not used as a selector and should not become one.

## Extraction pipeline

Use this sequence to locate the failing layer:

```text
discover backup
  -> parse Manifest.plist
  -> derive the backup-password key and unlock class keys
  -> decrypt/read Manifest.db
  -> locate KeychainDomain/keychain-backup.plist
  -> parse generic-password (genp) entries
  -> unwrap and decrypt Keychain records
  -> decode version 2 plist or version 3 ASN.1 fields
  -> identify Sakamichi records
  -> parse nested refreshToken JSON
  -> classify, deduplicate, and write tokens
```

### Code map

| Concern | Main implementation |
|---|---|
| CLI, backup discovery, diagnostics, record matching | `cmd/sakamichi-token-extractor/main.go` |
| Unit tests for discovery, matching, parsing, and permissions | `cmd/sakamichi-token-extractor/main_test.go` |
| Backup manifest and file decryption | `backup/backup.go` |
| Backup keybag/password derivation | `keybag/keybag.go` |
| AES key unwrapping | `crypto/aeswrap` |
| Keychain AES-GCM compatibility code | `crypto/gcm` |
| Version 3 Keychain ASN.1 decoding | `encoding/asn1` and `parseRecord` |
| NSKeyedArchive decoding for `Manifest.db` records | `kvarchive/keyed.go` |
| Native SQLite dependency | `github.com/mattn/go-sqlite3` in `go.mod` |
| Native release matrix and Windows compiler setup | `.github/workflows/release.yml` |

The backup, ASN.1, GCM, and keyed-archive packages contain old or compatibility-derived code. Inspect those local implementations before assuming current standard-library behavior applies.

## Compatibility assumptions

### Finder/iTunes backup assumptions

- The backup is local and encrypted. Unencrypted backups do not provide the required Keychain class keys.
- `Manifest.plist` contains `IsEncrypted`, `BackupKeyBag`, and, for current backups, `ManifestKey`.
- The keybag uses the currently understood TLV fields and password derivation: optional SHA-256 PBKDF2 followed by SHA-1 PBKDF2.
- Password-wrapped class keys use the supported wrapping type.
- Current backups use `Manifest.db`; legacy `Manifest.mbdb` has limited compatibility code.
- The `files` table remains compatible with the five positional fields currently scanned by `backup.readNewManifest`.
- Each `files.file` value remains an NSKeyedArchive containing the expected encryption key, protection class, size, mode, ownership, timestamps, and relative path fields.
- The backed-up Keychain remains at `KeychainDomain/keychain-backup.plist`.

### Keychain assumptions

- Generic-password records remain under the `genp` plist key.
- Each entry exposes encrypted data as `v_Data`.
- Encrypted record framing remains compatible with record versions 2 or 3.
- The protection class remains in the low four bits of the current class word.
- The per-record key remains AES-wrapped by an available backup class key.
- Version 2 plaintext remains a plist.
- Version 3 plaintext remains an ASN.1 SET containing key/value entries such as `svce`, `acct`, `agrp`, and `v_Data`.
- The token record remains backup-migratable. A `ThisDeviceOnly` class cannot be decrypted from a Finder backup because its key is not exported.

### App-storage assumptions

- The token remains in a generic-password Keychain record rather than an app-container database, native preferences, memory only, or Secure Enclave-bound storage.
- The record remains recognizable through the service, account, or access group.
- Current service: `flutter_secure_storage_service`.
- Historical account prefix supported by the code: `FC_TOKEN_KEY_`.
- Current account: `TOKEN_KEY`.
- Recognized identifiers include `smcms_token_key`, `sonymusic`, `keyakizaka`, `nogizaka`, and `sakurazaka`.
- The access group continues to contain one of the three bundle identifiers listed above.
- The record's plaintext `v_Data` remains UTF-8 JSON.
- A string field named a case/underscore variant of `refreshToken` exists somewhere in the JSON object or arrays. For example, `refreshToken` and `refresh_token` work; `refresh-token` currently does not.
- A token is still meaningful outside the app. Extraction can succeed while server-side device binding makes the credential unusable.

## Failure triage

First determine the last successful layer. Avoid changing record matching when the backup itself no longer decrypts.

| Symptom or diagnostic | Likely layer | First investigation |
|---|---|---|
| No backups discovered | Discovery | Check default MobileSync paths, symlinks, Full Disk Access, and `Manifest.plist` presence. |
| Backup is reported as unencrypted | Backup creation | Confirm Finder's “Encrypt local backup” option and create a fresh backup. |
| Password rejected | Keybag | Confirm the backup password; then compare keybag TLVs and password derivation with the known-good format. |
| Cannot load decrypted manifest | Manifest | Inspect `ManifestKey`, padding/decryption, SQLite schema, and keyed-archive decoding. |
| Panic or fatal exit while loading a new backup | Parser robustness | Search for `panic`, `log.Fatal`, positional SQL scans, and unchecked type assertions in `backup`, `keybag`, and `kvarchive`. |
| `keychain-backup.plist is absent` | Backup layout | Search manifest records for renamed Keychain domains/paths without dumping file contents. |
| `general_entries` is zero | Keychain plist | Inspect top-level plist keys and determine whether generic passwords moved or changed representation. |
| New value in `record_versions` and matching unsupported-version failures | Keychain record format | Compare record framing before modifying cryptography. Add a synthetic fixture and support the version explicitly. |
| Most records fail AES-GCM or key unwrapping | Keychain crypto | Check class extraction, key wrapping, nonce/tag layout, and whether the wrong file/key is being used. |
| Only classes 9–11 lack keys at roughly the baseline scale | Usually normal | Do not treat this alone as the cause; the known-good run had 1,762 such failures. |
| `decrypted_records` is healthy but `default_service_count` becomes zero | App storage | Look for new service names in redacted candidate metadata or exact known access groups. |
| `default_service_count` is nonzero but no recognized candidates | App identifiers | Compare account and access-group field names/values; update narrowly and add tests. |
| `refresh_token_json_count` is zero | Serialization/auth model | Determine whether `v_Data` is still JSON and whether the field name/type or token model changed. |
| Refresh-token JSON exists but no tokens are recovered | Matcher | Compare `targetRecord` with service/account/access group. Do not broadly emit every refresh token. |
| Token is recovered as `unclassified` | Bundle mapping | Update `appBundles` after confirming the exact new access group. |
| Only one app is missing | App-specific state | Confirm that app was installed, signed in, recently opened, and present when the fresh backup was made; compare its candidate identifiers with the other two. |
| Three tokens are written but rejected by the server | Server/authentication | Check expiry, rotation, client requirements, device binding, and API changes. The backup parser may be healthy. |

### High-value comparison matrix

When possible, retain a known-good backup and binary. Run this four-way comparison:

| Binary | Backup | What it isolates |
|---|---|---|
| Old known-good | Old known-good | Confirms the baseline and environment. |
| New | Old known-good | Extractor regression. |
| Old known-good | New | iOS/app/backup-format change. |
| New | New | Current user-visible result. |

Do not modify the old backup. A read-only copy is ideal.

## Safe evidence packet for an LLM or issue

Collect as many of these as possible:

1. Tool version and Git commit SHA.
2. Release archive name and SHA-256 checksum.
3. Host operating system and architecture.
4. iOS version and build number.
5. Exact version of each of the three Message apps.
6. Backup creation application/version and backup creation date.
7. Whether the backup was freshly created, local, and encrypted.
8. Whether each app was installed, signed in, and opened before the backup.
9. Whether any app was signed out, deleted, reinstalled, or restored recently.
10. The exact command, with private paths shortened or redacted.
11. Complete stdout/stderr with the device name and local paths redacted.
12. `diagnostics.json`.
13. `index.json` only after redacting `output_file` paths.
14. The last known-good combination of tool, iOS, app versions, and date.
15. Results of the old/new binary and old/new backup comparison above.
16. Whether extraction failed, recovered fewer apps, or recovered tokens that the server rejected.

Explicitly state which sensitive artifacts were withheld. This helps prevent a future model from repeatedly requesting unsafe data.

## Likely fixes by change type

### New backup or manifest format

- Replace `select * from files` with explicit column names if Apple changes the table.
- Replace unchecked keyed-archive type assertions with validated conversions and returned errors.
- Preserve unknown keyed-archive fields rather than panicking.
- Add schema/version information to diagnostics before changing decryption.

### New keybag fields or wrapping behavior

- `keybag.Read` currently terminates the process on unknown FourCC fields. Change this to preserve or skip length-delimited unknown fields and return structured errors where required.
- Add bounds checks before slicing each TLV.
- Record non-secret keybag version/type/wrap metadata in diagnostics.
- Do not claim backup extraction is possible if Apple stops exporting the required class key.

### New Keychain record version or ASN.1 field

- Record the version and failure count first.
- Create a synthetic record with dummy keys and a dummy token before modifying `decryptRecord`.
- Preserve partially decoded fields when safe, as `parseRecord` currently does for newer ASN.1 fields.
- Treat authentication failures as evidence of a framing/key/nonce mismatch, not as permission to ignore authentication tags.

### Renamed app identifiers

- Compare `svce`, `acct`, and `agrp` metadata from the failing run with the known-good table.
- Prefer an exact bundle access-group allowlist over broad keywords.
- Update `targetRecord`, `targetIdentifier`, and `appBundles` together.
- Add positive tests for each app and negative tests proving unrelated Sony Music credentials are not selected.

### Changed token serialization

- Determine whether the value is JSON, plist, protobuf, base64, or another encoding without logging its content.
- Add diagnostics for value type, parse success, top-level field names, and non-secret lengths.
- Extend `tokenFromRecord` and add dummy fixtures.
- Keep recursive JSON parsing, but avoid accepting arbitrary token-like strings without an app/access-group match.

### Different storage location

- Search backup metadata for the known app domains and likely SQLite/plist files.
- Inspect only user-authorized backups and minimize exposed data.
- Add a separate, explicit extraction path rather than silently scanning and dumping whole app containers.
- If the token moved to `ThisDeviceOnly`, Secure Enclave, or memory-only storage, document that backup recovery is not possible rather than weakening security checks.

### Recovered token rejected by the service

- Confirm whether the token is current, rotated, expired, or revoked.
- Compare the app's current refresh request requirements: client identifiers, headers, device attestation, proof-of-possession, and token binding.
- Keep this investigation separate from backup decryption. A valid extraction does not guarantee replayability.

## Known fragilities worth hardening proactively

These are not known failures in the current baseline, but they are likely maintenance hotspots:

1. `keybag.Read` uses `log.Fatal` for unknown fields and has limited malformed-length handling.
2. `backup.readNewManifest` uses `select *`, assumes a fixed column order/count, panics on archive errors, and contains unchecked type assertions.
3. `kvarchive` contains unchecked assumptions about Foundation class names and numeric representations.
4. Only Keychain record versions 2 and 3 are accepted.
5. The version 3 decoder is a vendored ASN.1 implementation with deliberate partial-decoding behavior.
6. Matching contains broad historical keywords that can create false positives if other Sony Music records contain refresh-token JSON.
7. The matching rules are compiled into the binary rather than represented as versioned app profiles.
8. Diagnostics have no explicit schema version or tool version.
9. The repository has unit tests but no committed synthetic end-to-end encrypted-backup fixture.
10. App versions are not discoverable from the current diagnostic report.

Recommended hardening order:

1. Replace fatal exits and panics on backup-controlled formats with structured errors and diagnostics.
2. Make manifest database reads schema-aware and use explicit columns.
3. Add diagnostics schema/tool versions and non-secret format metadata.
4. Build synthetic version 2 and version 3 encrypted Keychain fixtures with dummy tokens.
5. Move app identifiers and token-field rules into validated, versioned profiles while retaining a secure built-in allowlist.
6. Add tests for near-miss credentials and unrelated Sony Music records.
7. Record a redacted known-good baseline for every confirmed iOS/app-version combination.

## Testing a compatibility fix

At minimum run:

```shell
go test ./...
go vet ./...
```

A compatibility change should also include:

- a regression test that fails before the fix;
- dummy tokens only;
- positive coverage for all three apps when matching changes;
- negative coverage for unrelated credentials;
- verification against an old known-good backup and the new failing backup;
- confirmation that `diagnostics.json` and logs contain no token values;
- native release builds on every platform in `.github/workflows/release.yml`.

Never commit a real backup-derived encrypted record on the assumption that encryption makes it safe. Passwords can be weak, metadata can be identifying, and future disclosure can expose the plaintext.

## Suggested LLM handoff prompt

Use a prompt shaped like this and attach only the safe evidence packet:

```text
Analyze a compatibility failure in sakamichi-token-extractor. Do not request or
emit refresh tokens, access tokens, backup passwords, raw Keychain values, or a
complete iPhone backup. Start by identifying the last successful extraction
layer using MAINTENANCE.md and diagnostics.json. Compare the failure with the
known-good baseline, state the most likely broken assumption, and identify the
smallest code area and regression fixture needed for a safe fix. Distinguish
backup parsing, app storage matching, token serialization, and server rejection.

Tool version/commit:
Host OS/architecture:
iOS version/build:
Nogizaka app version:
Sakurazaka app version:
Hinatazaka app version:
Backup creator/date/encrypted:
Last known-good combination:
Exact redacted error/output:
Old/new binary and backup comparison:
```

Ask the model to explain why its proposed change cannot select unrelated credentials or weaken cryptographic authentication before accepting the patch.

## Updating this document

After confirming compatibility with a new iOS or app release:

1. Add the exact tool, iOS, and all three app versions to the known-good history.
2. Record redacted diagnostic counts and identifier changes.
3. Note whether old backups still work.
4. Link the regression test and compatibility commit.
5. Do not replace the last known-good baseline until the new result is reproduced.
