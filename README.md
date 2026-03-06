# enteauth-rs

Read TOTP/HOTP 2FA codes from a local [Ente Auth](https://ente.io/auth/) installation — no app, no network.

## Requirements

- Ente Auth installed and set up on Linux with a keyring (Tested with gnome keyring, report an issue if it fails with Kwallet)
- To sync new codes launch the Ente auth gui app.

## Features
- Seamless migration, assuming you aldready use ente-auth no extra configuration is needed.
- Practically no resource usage compared the original app.
- Fast

## Usage


Clone and build then run with

```sh
cargo build --release
# List all codes
./target/release/enteauth-rs 
# Get a specific code and copy to clipboard if unique
./target/release/enteauth-rs <query>
```
`--no-copy` and `--json` available as options.
Tries to use wl-copy, xclip and xsel to copy the code. Codes are copies automatically only if the query returns a simple output.


Available on AUR [enteauth-rs-git](https://aur.archlinux.org/packages/enteauth-rs-git)

## How it works

Reads the encrypted Ente Auth SQLite database at `~/.local/share/io.ente.auth/.ente.authenticator.db`, decrypts each entry using the key from Keyring, and computes the current code.


## Related work
- [ctotp](https://github.com/GibreelAbdullah/ctotp) Similar functions but uses ente-cli for the initial sync.
