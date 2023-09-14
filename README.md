## zipsign: Sign a file with an ed25519ph signing key

### Install

```text
cargo install --git https://github.com/Kijewski/zipsign
```

### Example

* .zip:

    ```sh
    # Generate key pair:
    $ zipsign gen-key priv.key pub.key

    # ZIP a file and list the content of the ZIP file:
    $ zip Cargo.lock.zip Cargo.lock
    $ unzip -l Cargo.lock.zip
    Cargo.lock

    # Sign the ZIP file:
    $ zipsign sign zip -o Cargo.lock.signed.zip Cargo.lock.zip priv.key
    $ mv Cargo.lock.signed.zip Cargo.lock.zip
    $ unzip -l Cargo.lock.zip
    Cargo.lock

    # Verify that the generated signature is valid:
    $ zipsign verify zip Cargo.lock.zip pub.key
    OK
    ```

* .tar:

    ```sh
    # Generate key pair:
    $ zipsign gen-key priv.key pub.key

    # TAR a file and list the content of the ZIP file:
    $ tar czf Cargo.lock.tgz Cargo.lock
    $ tar tzf Cargo.lock.tgz
    Cargo.lock

    # Sign the .tar.gz file:
    $ zipsign sign tar -o Cargo.lock.signed.tgz Cargo.lock.tgz priv.key
    $ mv Cargo.lock.signed.tgz Cargo.lock.tgz
    $ tar tzf Cargo.lock.tgz
    Cargo.lock

    # Verify that the generated signature is valid:
    $ zipsign verify tar Cargo.lock.tgz pub.key
    OK
    ```

### Generate key

Usage: `zipsign gen-key <PRIVATE_KEY> <VERIFYING_KEY>`

Arguments:

* `PRIVATE_KEY`:    Private key file to create
* `VERIFYING_KEY`:  Verifying key (public key) file to create

Options:

* `-e`, `--extract`: Don't create new key pair, but extract public key from private key
* `-f`, `--force`: Overwrite output file if it exists

### Sign a .zip or .tar.gz file

Usage: `zipsign sign [zip|tar] -o <SIGNED_FILE> <INPUT> <KEYS>...`

Subcommands:

* `zip`: Sign a .zip file
* `tar`: Sign a .tar.gz file

Options:

* `-o`, `--output <OUTPUT>`:   Signed file to generate
* `-c`, `--context <CONTEXT>`: Arbitrary string used to salt the input, defaults to file name of `<INPUT>`
* `-f`, `--force`: Overwrite output file if it exists

Arguments:

* `<INPUT>`:   Input file to sign
* `<KEYS>...`: One or more files containing private keys

### Verify a signature

Usage: `zipsign verify [zip|tar] <INPUT>`

Subcommands:

* `zip`: Verify a signed `.zip` file
* `tar`: Verify a signed `.tar.gz` file

Options:

* `-c`, `--context <CONTEXT>`: An arbitrary string used to salt the input, defaults to file name of `<INPUT>`
* `-q`, `--quiet`:             Don't write "OK" if the verification succeeded

Arguments:

* `<INPUT>`:   Signed `.zip` or `.tar.gz` file
* `<KEYS>...`: One or more files containing verifying keys

### How does it work?

The files are signed with one or more private keys using [ed25519ph](https://datatracker.ietf.org/doc/html/rfc8032#section-5.1).
The signatures are stored transparently next to the data.

For .tar.gz files the signatures are encoded as [base64](https://datatracker.ietf.org/doc/html/rfc4648#page-5) string.
The string gets encapsulated as the comment of a GZIP file, and this GZIP file is appended to the input document.
This works, because multiple GZIP files can be freely concatenated.

For .zip files the signature gets prepended to the input document.
This works because ZIP files can be prepended with any data as long as all relative addresses are fixed up afterwards.
This feature is used e.g. self-extracting ZIP files.
