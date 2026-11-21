# My ARTfive! Android packaging (Preview only)

This directory is isolated Android packaging work. It does not modify the railway app pages, styles, features, Worker logic, database schema, or existing deployment workflows.

## Approved application identity

- Android application ID: `in.myartfive.railwayassistant`
- Display name: `My ARTfive! Railway Assistant`
- Launcher label: `My ARTfive!`
- Android packaging: Trusted Web Activity (TWA) generated with Bubblewrap
- PWA manifest: `https://my-artfive-railway-assistant-preview.myartfiverailwayassistant.workers.dev/manifest.webmanifest`
- App origin: `https://my-artfive-railway-assistant-preview.myartfiverailwayassistant.workers.dev`
- Start URL: `/`
- Backend: existing Preview Worker and Preview D1 database only

## Important protection

Do not point this Android package at the production Worker or production D1 database. Do not deploy the production Worker. Do not edit the existing app UI or application logic as part of Android packaging.

The public Play Store app will continue to use Preview data while this Preview origin is configured. Preview is therefore the live backend for customers until a separate, explicitly approved production migration is requested.

## Build prerequisites

- Node.js 18 or later
- Java 17
- Android SDK / Build Tools
- Bubblewrap CLI 1.25.0 or later (the 1.25.0 release includes Android target SDK 36)
- A private Android upload keystore, created and retained by the owner

Install Bubblewrap:

```sh
npm install --global @bubblewrap/cli@1.25.0
```

Initialize the TWA project from the Preview web manifest:

```sh
mkdir -p android-build
cd android-build
bubblewrap init --manifest https://my-artfive-railway-assistant-preview.myartfiverailwayassistant.workers.dev/manifest.webmanifest
```

During initialization, use the approved application ID `in.myartfive.railwayassistant`, app name `My ARTfive! Railway Assistant`, launcher name `My ARTfive!`, and Preview origin above. Keep the generated signing keystore private; do not upload it to GitHub or send its password/private key in chat.

Build outputs:

```sh
bubblewrap build
```

Bubblewrap generates a signed APK for direct Android testing and an Android App Bundle (AAB) for Google Play. Verify the generated Android Gradle project targets API 36 or higher before any Play Console upload.

## Digital Asset Links (required for full-screen TWA)

After the signing key is created, obtain its SHA-256 certificate fingerprint. Generate the matching `assetlinks.json` entry for package ID `in.myartfive.railwayassistant`. The file must be served from:

`https://my-artfive-railway-assistant-preview.myartfiverailwayassistant.workers.dev/.well-known/assetlinks.json`

The fingerprint must match the certificate used by the installed APK. If Google Play App Signing is enabled, configure both the upload certificate and the Play app-signing certificate as appropriate. Do not publish placeholder fingerprints. Do not commit any private signing material.

The assetlinks file is not included until the real signing fingerprint is available. Full-screen TWA verification and final signed builds remain pending that step.

## Release safeguards

- APK: for owner-controlled direct installation/testing.
- AAB: for Google Play Console submission.
- Do not submit or publish to any Play track without the owner's explicit instruction.
- Do not trigger the Preview deployment workflow automatically. The owner must manually run the approved Preview deployment process.
- Never use production D1 or production Worker bindings for this package.
