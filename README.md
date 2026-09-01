# Sakamichi Token Extractor

Recover the refresh tokens currently used by the Sakamichi Message apps from an encrypted local iPhone backup—without jailbreaking the phone or intercepting its network traffic.

Supported apps:

- Nogizaka46 Message (`jp.co.sonymusic.communication.nogizaka`)
- Sakurazaka46 Message (`jp.co.sonymusic.communication.sakurazaka`)
- Hinatazaka46 Message (`jp.co.sonymusic.communication.keyakizaka`)

The tool runs locally. At runtime it does not contact the apps' servers, upload backup data, modify the backup, or dump the complete iPhone Keychain.

## Responsible use

Only use this tool with a device, backup, and accounts that you own or are explicitly authorized to access.

A refresh token is a bearer credential. Anyone who obtains one may be able to access the associated account until the token expires or is revoked. Never paste tokens into issue reports, commit them to Git, upload them to cloud storage, or share the encrypted-backup password.

## Requirements

- An **encrypted** local backup created by Finder, iTunes, or another compatible backup application. Unencrypted backups do not contain usable Keychain material.
- The encrypted-backup password.
- For source builds: Go 1.19 or newer and a C toolchain, because the backup reader uses `go-sqlite3`/CGO.
  - macOS: Xcode Command Line Tools.
  - Linux: the distribution's compiler/build-essential package.
  - Windows: a supported GCC/MinGW environment.

## Download or build

Prebuilt macOS, Linux, and Windows binaries are published on the [GitHub Releases](https://github.com/AzureOSK/sakamichi-token-extractor/releases) page. Each release also includes a `SHA256SUMS` file for verifying downloads.

To build from source:

```shell
git clone https://github.com/AzureOSK/sakamichi-token-extractor.git
cd sakamichi-token-extractor
make build
```

The executable is created at `bin/sakamichi-token-extractor`.

You can also build directly:

```shell
go build -trimpath -o ./bin/sakamichi-token-extractor ./cmd/sakamichi-token-extractor
```

## Create an encrypted backup

On macOS, connect the iPhone and open it in Finder. Select "Back up all of the data on your iPhone to this Mac," enable "Encrypt local backup," and create a fresh backup.

Do not sign out of, delete, or reinstall a Message app before backing up; doing so may remove or revoke the token you want to recover.

## Usage

On macOS and Windows, the command checks the normal MobileSync backup locations. If exactly one backup is found:

```shell
./bin/sakamichi-token-extractor
```

List discoverable backups:

```shell
./bin/sakamichi-token-extractor --list-backups
```

Select a device backup explicitly, including one stored on an external drive:

```shell
./bin/sakamichi-token-extractor \
  --backup "/path/to/MobileSync/Backup/device-id"
```

The `--backup` value may also be a directory containing several device-backup directories. If more than one backup is found, the command lists them and asks you to choose one explicitly.

Choose a persistent output directory instead of the default fresh temporary directory:

```shell
./bin/sakamichi-token-extractor \
  --backup "/path/to/device-id" \
  --output "/path/to/private/output"
```

The backup password is read from a hidden terminal prompt. Neither the password nor its derived key is logged or written to disk.

If macOS reports `Operation not permitted` for the MobileSync directory, give the terminal application Full Disk Access or pass a copy of the device-backup directory using `--backup`.

## Output

Depending on which apps are present and signed in, the output directory can contain:

```text
hinatazaka_refresh_token.txt
nogizaka_refresh_token.txt
sakurazaka_refresh_token.txt
index.json
diagnostics.json
```

`index.json` contains app classification and Keychain metadata but no token values. `diagnostics.json` contains record counts and decoding failures but no Keychain values.

On Unix-like systems, the output directory is mode `0700` and files are mode `0600`. Windows uses the account permissions inherited by newly created files and directories.

## How it works

The command:

1. Unlocks the backup keybag with the locally entered backup password.
2. Decrypts `Manifest.db` and locates `KeychainDomain/keychain-backup.plist`.
3. Decrypts backup-migratable generic-password records in memory.
4. Selects only Flutter Secure Storage records matching the three Sakamichi app access groups and token-key identifiers.
5. Writes only JSON values containing a `refreshToken`/`refresh_token` field.

It does not bypass certificate pinning or extract live process memory.

## Limitations

- `ThisDeviceOnly` Keychain records cannot be decrypted from a backup because their keys remain bound to the physical device.
- The Sakamichi apps currently use a backup-migratable Keychain class for these tokens. A future app update could change the storage key, serialization, accessibility class, or authentication flow.
- A token may already be expired or revoked by the server.
- Only local Finder/iTunes-style backups are supported; iCloud backups are not downloaded by this project.

## Development

Run all tests and static checks:

```shell
go test ./...
go vet ./...
```

The test suite covers backup discovery, app/access-group classification, refresh-token parsing, and output permissions.

### Publishing a release

The release workflow runs when a tag beginning with `v` is pushed. It tests and builds natively on macOS, Linux, and Windows runners, packages the executable with its documentation and license notices, generates SHA-256 checksums, and publishes the matching GitHub Release.

For example:

```shell
git tag -a v0.1.3 -m "Sakamichi Token Extractor v0.1.3"
git push origin v0.1.3
```

The version reported by `sakamichi-token-extractor --version` is taken from the tag name during release builds. Local builds report `dev` unless a version is supplied explicitly, such as `make build VERSION=0.1.0`.

## Attribution and license

The iOS backup and Keychain decryption code is derived from Steve Dunham's [`dunhamsteve/ios`](https://github.com/dunhamsteve/ios) project and earlier `iphone-dataprotection` work. The original code is MIT licensed. The bundled ASN.1 and modified GCM packages are derived from Go standard-library code under the BSD license.

See [LICENSE](LICENSE) for the retained notices and license terms.
