import fs, { writeFile, type FileHandle } from 'node:fs/promises'
import crypto from 'node:crypto'
export interface MatchResult {
    url: string
    matched: boolean
}
export class SafeBrowsing {
    public fileHandle?: FileHandle;
    public fileSize?: number;
    public prefixSize = 4
    public apiKey: string = ''

    static async open(filePath: string) {
        const sb = new SafeBrowsing()
        await sb.open(filePath)
        return sb
    }
    async close() {
        if (this.fileHandle) {
            await this.fileHandle.close()
        }
    }
    async open(filePath: string) {
        const file = await fs.open(filePath, 'r');
        this.fileHandle = file
        this.fileSize = (await file.stat()).size;
        return this
    }
    static setKey(key: string) {
        return new SafeBrowsing().setKey(key)
    }
    setKey(key: string) {
        this.apiKey = key
        return this
    }
    find(urls: string[]): Promise<MatchResult>;
    find(url: string): Promise<MatchResult>;
    async find(url: string | string[]) {
        if (Array.isArray(url)) {
            return await Promise.all(url.map(this.find.bind(this)))
        }
        if (!this.fileSize || !this.fileHandle) {
            throw new Error('file does not loaded yet')
        }
        const hash = this.getHash(url)
        let left = 0;
        let right = Math.floor(this.fileSize / this.prefixSize) - 1;
        const buffer = Buffer.alloc(this.prefixSize);

        while (left <= right) {
            const mid = Math.floor((left + right) / 2);
            await this.fileHandle.read(buffer, 0, this.prefixSize, mid * this.prefixSize);
            const cmp = buffer.compare(hash, 0, this.prefixSize);
            if (cmp === 0) {
                return {
                    url,
                    matched: true
                };
            } else if (cmp < 0) {
                left = mid + 1;
            } else {
                right = mid - 1;
            }
        }
        return {
            url,
            matched: false
        }
    }
    getHash(url: string) {
        const hash = crypto.createHash('sha256');
        hash.update(url, 'utf-8')
        return Buffer.from(hash.digest())
    }
    async downloadTo(filePath: string) {
        const url = 'https://safebrowsing.googleapis.com/v4/threatListUpdates:fetch'
        const res = await fetch(url+'?key='+this.apiKey, {
            method: 'POST',
            headers: {
                'content-type':"application/json",
                "Content-Encoding": "gzip"
            },
            body: JSON.stringify({
                "client": {
                  "clientId":       "safe-browsing"
                },
                "listUpdateRequests": [{
                  "threatType":     "SOCIAL_ENGINEERING",
                  "platformType":    "ANY_PLATFORM",
                  "threatEntryType": "THREAT_ENTRY_TYPE_UNSPECIFIED"
                }]
              })
        })
        if (!res.ok) {
            throw new Error('download failed')
        }
        const result = await res.json()
        const rawHashes = (result as any)?.listUpdateResponses?.[0].additions?.[0].rawHashes?.rawHashes
        if (!rawHashes) {
            throw new Error('Failed to download')
        }
        const hashes = Buffer.from(rawHashes, 'base64')
        return await writeFile(filePath, hashes)
    }
}