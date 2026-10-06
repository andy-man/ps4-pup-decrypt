## About this fork

This repository is a fork of [andy-man/ps4-pup-decrypt](https://github.com/andy-man/ps4-pup-decrypt).

The goal of this fork is to improve reliability, progress reporting, and diagnostics while preserving the original PUP decryption behavior.


##### (*WAS ONLY TESTED FOR RETAIL 13.52 DECRYPTING 14.00*)


### Changes in this fork

- Fixed freeze on payload deploy.
- Added persistent decryption status reporting to:
  - `/mnt/usb0/pup_decrypt.status`
- Added completion markers for successfully decrypted entries:
  - `PS4UPDATE1.PUP.dec.ok`
  - `PS4UPDATE2.PUP.dec.ok`
  - etc.
- Added error propagation from lower-level decryption functions to the payload entry point.
- Added allocation failure checks.
- Reduced excessive per-block notification output.
- Added periodic progress reporting during block decryption.
- Improved distinction between successful completion and partial/failed output.
- Adjusted project include ordering for compatibility with the current PS4 Payload SDK.

The actual PUP decryption algorithm and PS4 encryption-service interaction are intentionally kept as close to the upstream implementation as possible.

## Status files

While the payload is running, the USB drive contains:

```text
/mnt/usb0/pup_decrypt.status
```

Example running state:

```text
RUNNING
entry=PS4UPDATE2.PUP
entry_number=2/4
stage=decrypt_block
segment=7
block=145/820
percent=17
```

Successful completion produces:

```text
DONE
```

If an error occurs, the status file contains information about the entry and stage at which the failure occurred.

A successfully completed output also receives a corresponding `.ok` marker. For example:

```text
PS4UPDATE1.PUP.dec
PS4UPDATE1.PUP.dec.ok
```

A `.dec` file without its `.ok` marker should be considered potentially incomplete.

## Building

A recent version of the PS4 Payload SDK is required.

Set the SDK path:

```bash
export PS4SDK=/opt/ps4sdk
```

Then build:

```bash
make
```

The resulting `.bin` payload is written to the repository root.
