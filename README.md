# ps4-pup-decrypt
Payload to decrypt the contents of a firmware update file (PUP) on the PlayStation 4

The default (hardcoded) operation is to decrypt `/mnt/usb0/safe.PS4UPDATE.PUP` to `/mnt/usb0/entryname.dec`.

This will only decrypt >= current firmware version installed, latest tested (installed) firmware is 11.05.

This will output a number of files (depending if a normal or a recovery update):
* `/mnt/usb0/PS4UPDATE1.PUP.dec`
* `/mnt/usb0/PS4UPDATE2.PUP.dec`
* `/mnt/usb0/PS4UPDATE3.PUP.dec`
* `/mnt/usb0/PS4UPDATE4.PUP.dec`

These decrypted updates can then be unpacked using [pup_unpack](https://github.com/idc/ps4-pup_unpack/).

## Notes
To build, you will need [a recent fork of ps4-payload-sdk](https://github.com/Scene-Collective/ps4-payload-sdk).

The PS4 will refuse to decrypt updates in some cases:
* Versions older than the installed version (for the most part, there's exceptions for things like beta versions).
* Versions for a different product code (retail cannot decrypt test or debug updates).
