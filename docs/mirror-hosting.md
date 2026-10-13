# Hosting the fallback download host (usedenis.com)

This file is for the person who runs the project's release pipeline. It is not part of the product's
customer documentation. DENIS asks `https://usedenis.com` for updates only when GitHub cannot be reached
(see [Updates](updates.md)). The files are held in a Cloudflare R2 bucket and served by a Cloudflare
Worker. Nothing in the repository holds a key: the signing key stays in the existing GitHub secret
`DENIS_RELEASE_KEY`, and the four R2 values below are GitHub secrets too.

If the four secrets are not set, the release pipeline skips the mirror upload and the release still goes
out normally. Setting them up is optional and can be done at any time; the mirror is filled at the next
release (or by hand, step 6).

## What goes where

| What | Where |
|---|---|
| The program files, signed list and manifest | an R2 bucket, written by the release pipeline (`tools/publish-mirror.sh`) |
| The public address `https://usedenis.com/releases/...` | a Worker route in the website's Cloudflare account, which only reads the bucket |
| The release signing key | GitHub secret `DENIS_RELEASE_KEY` (already exists), never in R2 and never in the Worker |

## 1. Create the R2 bucket

1. Cloudflare dashboard, **R2 Object Storage**, **Create bucket**.
2. Name it, for example `denis-releases`. Location: automatic. Leave **public access off** (no `r2.dev`
   address, no custom domain on the bucket): only the Worker reads it.
3. Note the bucket name (it becomes the secret `R2_BUCKET`) and your **Account ID** (shown on the R2
   overview page, right side; it becomes `R2_ACCOUNT_ID`).

## 2. Create an API token that can write to this bucket only

1. R2 Object Storage, **Manage API tokens** (or **Manage R2 API Tokens**), **Create API token**.
2. Permission: **Object Read & Write**.
3. **Specify bucket(s)**: choose only the bucket from step 1. Do not give it access to all buckets.
4. Create it. Cloudflare shows the **Access Key ID** and the **Secret Access Key** once. Copy both now
   (they become `R2_ACCESS_KEY_ID` and `R2_SECRET_ACCESS_KEY`). Ignore the "token value" and the
   jurisdiction endpoint; the pipeline builds `https://<account id>.r2.cloudflarestorage.com` itself.

## 3. Add the four GitHub secrets

In the repository that runs the release workflow (the source repository, not the public one):
**Settings, Secrets and variables, Actions, New repository secret**, four times:

| Secret | Value |
|---|---|
| `R2_ACCOUNT_ID` | the Account ID from step 1 |
| `R2_ACCESS_KEY_ID` | from step 2 |
| `R2_SECRET_ACCESS_KEY` | from step 2 |
| `R2_BUCKET` | the bucket name from step 1 |

`DENIS_RELEASE_KEY` must already be set (the release pipeline needs it anyway); the mirror job uses it to
sign the manifest.

## 4. The Worker route

In the website repository (you deploy it yourself with `wrangler deploy`): bind the bucket to the Worker
(`[[r2_buckets]]`, binding name of your choice, `bucket_name` from step 1) and route
`usedenis.com/releases/*` to it. The Worker must serve exactly this, read-only:

| Request | Answer |
|---|---|
| `GET` and `HEAD /releases/latest.json` | the object `releases/latest.json`, status 200, `Content-Type: application/json` |
| `GET` and `HEAD /releases/<version>/<file>` | the object `releases/<version>/<file>`, status 200 |
| anything else | status 404 (no listing, no other paths, no other methods) |

Rules the program relies on:

* `<version>` matches `^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$`, for example `4.1.0` or `4.1.0-rc.1`.
  `<file>` is `SHA256SUMS`, `SHA256SUMS.sig` or `denis-<platform>` (letters, digits, `-`, `_`, `.`).
  Refuse anything with `..` or a second slash, and map the path to the same key in the bucket.
* **Never redirect.** DENIS refuses any redirect from this host (a redirect to another host would be a way
  to send an update somewhere else). Answer 200 with the body, or 404.
* HTTPS only. Send `Content-Length`. A binary is up to about 60 MB; the program refuses anything above
  300 MB, and a manifest above 256 KB.
* Caching is yours to choose. The pipeline uploads version folders with a one-year `immutable` cache
  header (a version's files never change) and `latest.json` with `max-age=300`; the Worker may pass these
  on. `latest.json` must not be cached for long, or a new release reaches the mirror late.
* Do not rewrite, compress differently or "pretty print" any file: the signature on `latest.json` covers
  its exact bytes, and the checksums cover the programs.

A reference Worker (adapt freely; it is an example, not part of this repository's build):

```js
export default {
  async fetch(request, env) {
    if (request.method !== 'GET' && request.method !== 'HEAD') return new Response('not found', { status: 404 });
    const path = new URL(request.url).pathname;
    const ok = path === '/releases/latest.json' ||
      /^\/releases\/[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?\/(SHA256SUMS|SHA256SUMS\.sig|denis-[A-Za-z0-9_.-]+)$/.test(path);
    if (!ok) return new Response('not found', { status: 404 });
    const obj = await env.RELEASES.get(path.slice(1));   // binding name from wrangler.toml
    if (!obj) return new Response('not found', { status: 404 });
    const h = new Headers();
    obj.writeHttpMetadata(h);
    h.set('etag', obj.httpEtag);
    return new Response(request.method === 'HEAD' ? null : obj.body, { status: 200, headers: h });
  },
};
```

## 5. What the pipeline puts in the bucket

After a release is published on GitHub, the `mirror` job of `.github/workflows/release.yml` runs
`tools/publish-mirror.sh`, which:

1. reads the current `releases/latest.json` (if any);
2. builds the new signed manifest with `denis release-manifest` (the release folder's own signature must
   verify with the release key built into the program, or nothing is uploaded);
3. uploads `releases/<version>/` (the `denis-<platform>` programs, `SHA256SUMS`, `SHA256SUMS.sig`);
4. uploads `releases/latest.json` last, so it never names files that are not there yet;
5. removes every other version folder: **only the newest stable and the newest pre-release are kept**
   (a stable release that overtakes a pre-release removes it).

The manifest is a JSON object `{"format":1,"payload":"<text>","signature":"<hex>"}`. `payload` is a string
holding a second JSON document (the versions, per-platform file names, sizes and SHA-256, and the release
notes) and `signature` is the Ed25519 signature, made with the release key, over the exact bytes of that
string. The format and the checks are documented at the top of `src/update_mirror.rs`.

## 6. Publishing by hand (backup path)

If the pipeline step did not run (secrets added after a release, or a failed upload), publish a finished
release from your own machine. You need the AWS command line tool (`aws`), the four R2 values and the
signing key in your environment, and the release's files in one folder (download them from the GitHub
release: `SHA256SUMS`, `SHA256SUMS.sig` and the `denis-*` programs):

```bash
export R2_ACCOUNT_ID=... R2_ACCESS_KEY_ID=... R2_SECRET_ACCESS_KEY=... R2_BUCKET=...
export DENIS_RELEASE_KEY=...        # the private release key; do not put it in a file in the repository
tools/publish-mirror.sh --version 4.1.0 --dir ./release-files --denis ./release-files/denis-x86_64-unknown-linux-gnu
# add --dry-run first to see what would be written
```

Run the program you pass with `--denis` on a machine where it can run (it is only used to build and sign
the manifest). Add `--notes notes.md` to carry the release notes into the manifest.

## 7. Check that it works

```bash
curl -sI https://usedenis.com/releases/latest.json          # 200, application/json, no Location header
curl -s  https://usedenis.com/releases/latest.json | head -c 300
curl -sI https://usedenis.com/releases/4.1.0/SHA256SUMS     # 200
```

Then, on a test installation: block `api.github.com` (for example in `/etc/hosts`), press **Check for
updates now** in Settings, System, Updates. The status line says GitHub could not be reached and
usedenis.com answered. Undo the block afterwards.

## 8. Changing or removing it

* Rotate the R2 token: create a new one (step 2), replace the two secrets, delete the old token.
* Stop publishing to the mirror: delete any one of the four secrets. The job then skips itself.
* Remove the mirror entirely: also remove the Worker route. Installations that cannot reach it simply
  keep using GitHub; nothing else changes. (The setting in each installation can also be switched off.)
