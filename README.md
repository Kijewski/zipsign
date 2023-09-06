## zipsign: Sign a file with an ed25519 signing key

### Install

```text
cargo install --git https://github.com/Kijewski/zipsign
```

### Verify a signature

Usage: `zipsign verify <VERIFYING_KEY> <FILE> <SIGNATURE>`

Arguments:

* `VERIFYING_KEY`:  Verifying key
* `FILE`:           Signed file
* `SIGNATURE`:      Signature file or .zip file generated with "zip" command

### Generate key

Usage: `zipsign gen-key <PRIVATE_KEY> <VERIFYING_KEY>`

Arguments:

* `PRIVATE_KEY`:    Private key file to create
* `VERIFYING_KEY`:  Verifying key (public key) file to create

### Zip a file and store its signature in the .zip

Usage: `zipsign zip [OPTIONS] <PRIVATE_KEY> <FILE> <ZIP>`

Arguments:

* `PRIVATE_KEY`:  Private key
* `FILE`:         File to sign
* `ZIP`:          ZIP file to (over)write

Options:

* `--method <METHOD>`: Compression method (stored | \*deflated | bzip2 | zstd, \*=default)
* `--level <LEVEL>`: Compression level
* `--permissions <PERMISSIONS>`: Unix-style permissions (default=0o644)

### Generate signature in new file

Usage: `zipsign sign <PRIVATE_KEY> <FILE> <SIGNATURE>`

Arguments:

* `PRIVATE_KEY`:  Private key
* `FILE`:         File to sign
* `SIGNATURE`:    Signature to (over)write
