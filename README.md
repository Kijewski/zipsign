## zipsign: Sign a file with an ed25519ph signing key

### Install

```text
cargo install --git https://github.com/Kijewski/zipsign
```

### Example

```sh
# Generate key pair:
$ zipsign gen-key priv.key pub.key

# ZIP a file and list the content of the ZIP file:
$ 7z a Cargo.lock.zip Cargo.lock
$ 7z l Cargo.lock.zip
Cargo.lock

# Sign the ZIP file:
$ zipsign sign -k priv.key -i Cargo.lock.zip -o Cargo.lock.tmp -c Cargo.lock --zip
$ mv Cargo.lock.tmp Cargo.lock.zip
$ 7z l Cargo.lock.zip
Cargo.lock

# Verify that the generated signature is valid:
$ zipsign verify -k pub.key -i Cargo.lock.zip -c Cargo.lock
OK
```

### Generate key

Usage: `zipsign gen-key <PRIVATE_KEY> <VERIFYING_KEY>`

Arguments:

* `PRIVATE_KEY`:    Private key file to create
* `VERIFYING_KEY`:  Verifying key (public key) file to create

### Generate signatures

Usage: `zipsign sign -k <PRIVATE_KEY> -i <INPUT> -o <SIGNATURE> [OPTIONS]`

Arguments:

Options:

* `-i`, `--input <INPUT>`:              File to verify
* `-o`, `--signature <SIGNATURE>`:      Signature to (over)write
* `-k`, `--private-key <PRIVATE_KEY>…`: One or more files containing private keys
* `-c`, `--context <CONTEXT>`:          Context (an arbitrary string used to salt the input, e.g. the basename of `<INPUT>`)
* `-z`, `--zip`:                        `<INPUT>` is a ZIP file. Copy its data into the output
* `-e`, `--end-of-file`:                Signatures at end of file (.tar files)

### Verify a signature

Usage: `zipsign verify -k <VERIFYING_KEY> -i <INPUT> [-o <SIGNATURE>] [OPTIONS]`

Arguments:

* `-i`, `--input <INPUT>`:                  File to verify
* `-o`, `--signature <SIGNATURE>`:          Signature file. If absent the signature it is read from `<INPUT>`
* `-k`, `--verifying-key <VERIFYING_KEY>…`: One or more files containing verifying keys
* `-z`, `--zip`:                            `<INPUT>` is a ZIP file. Copy its data into the output
* `-e`, `--end-of-file`:                    Signatures at end of file (.tar files)
