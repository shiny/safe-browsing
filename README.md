# Safe Browsing

## Installation

```bash
bun install @shiny/safe-browsing
```

This project solves a key problem: detecting malicious URLs without using HTTP APIs.
Instead, it uses the v4/threatListUpdates:fetch API to download threat data and stores URL hashes in a local binary file as a database.

> This project is still in the early validation stage, but it's already being used in u301.com to block user-generated malicious URLs.

Features
[x] Local URL lookup
[x] Download hashes and store as a binary file
[ ] URL Canonicalization [^1]
[ ] Incremental updates to local database
[ ] Support for all threat types
[ ] Support for Safe Browsing V5 API

## Download to Local Binary File

[Setup an API Key](https://support.google.com/cloud/answer/6158862?hl=en&ref_topic=6262490), then download the full hash database from the Safe Browsing API:

```typescript
import { SafeBrowsing } from '@shiny/safe-browsing'

const apiKey = '<MY_SAFE_BROWSING_KEY>'
const filePath = 'data/sb.bin'
await  SafeBrowsing
    .setKey(apiKey)
    .downloadTo(filePath)
```

## Match a URL

```typescript
import { SafeBrowsing } from '@shiny/safe-browsing'
const filePath = 'data/sb.bin'

const safeBrowsing = await SafeBrowsing.open(filePath)
const isPhishing = await safeBrowsing.find('testsafebrowsing.appspot.com/s/phishing.html')
console.log('isPhishing: ', isPhishing)
```

^[1]: https://developers.google.com/safe-browsing/v4/urls-hashing#canonicalization