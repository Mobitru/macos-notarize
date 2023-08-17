# Notarization tool

In order to distribute MacOS packages properly, they need to be notarized.

This tool performs the notarization procedure using Apple's Notary API.
It is supposed that executables are already signed and installer
package is created.

Notarization only uploads the file to Apple server, where Apple
software checks for any issues, and, if none found, records
the file hash to satifsy Gatekeeper software that checks
notarization from user's Mac when she downloads installer and
runs it.

There's a step that staples notary ticket to installer package
so Gatekeeper can work without internet connection.

## Prerequesites

First of all, create App Store API key at
[Apple store](https://appstoreconnect.apple.com/access/api)
(Users & Access -> Keys). Download the private key file (.p8 format)
and take a note of Key ID and Issuer ID.

## Build

```sh
go build -o ./notarize .
```

This will create `notarize` executable in the repository root folder.

## Notarize

```sh
./notarize -key-id $KEY_ID -key-file $PRIVATE_KEY_FILE_NAME -issuer $ISSUER_ID -file $FILE_TO_NOTARIZE 
```

During notarization submission ID will be created that is printed to the console.
Whenever you need to check status & progress of notarization again, you can run

```sh
./notarize -key-id $KEY_ID -key-file $PRIVATE_KEY_FILE_NAME -issuer $ISSUER_ID -submission-id $SUBMISSION_ID 
```

## Staple notary ticket for offline use (requires MacOS & Xcode)

```sh
xcrun stapler staple $FILE_TO_NOTARIZE
```

That's all. You're good to distrubute your package.
