# advisories.json.gz on GitHub Pages

The workflow [`publish-advisories-json.yml`](../.github/workflows/publish-advisories-json.yml)
turns the gem advisories of the public RubySec database
(<https://github.com/rubysec/ruby-advisory-db>) into one gzipped JSON file
and publishes it on GitHub Pages at a stable URL.

A Ruby program can then check the versions of its gems against the known
advisories with the standard library only: no Bundler, no bundler-audit, no
clone of the source repository and no YAML parsing on the client.

## Published URLs

With the default Pages domain of this repository:

| File | URL |
| --- | --- |
| Data | <https://syadem.github.io/ruby-advisory-db/advisories.json.gz> |
| Manifest | <https://syadem.github.io/ruby-advisory-db/manifest.json> |

The general form is `https://<owner>.github.io/<repository>/advisories.json.gz`
(owner in lower case). With a custom Pages domain, use that domain instead;
the URL is printed in the summary of every deployment (`deploy` job,
*github-pages* environment).

Both files are published in the same Pages deployment, so the manifest
always describes the data file served next to it.

## Enabling GitHub Pages (once)

1. *Settings > Actions > General*: allow GitHub Actions to run. On a fork,
   also open the *Actions* tab and enable workflows: GitHub disables
   scheduled workflows on forks until you do.
2. *Settings > Pages > Build and deployment > Source*: choose
   **GitHub Actions** (not "Deploy from a branch").
3. *Actions > Publish advisories.json > Run workflow* on `master` for the
   first deployment, or wait for the next quarter-hour.

The *github-pages* environment created by step 2 only accepts deployments
from the default branch. Run the workflow from `master`.

Until Pages is enabled, scheduled runs end with a warning and deploy
nothing; manual runs fail with an explanation.

## How the workflow works

The workflow runs every 15 minutes, on demand (*Run workflow*) and on every
push to `master` that changes the generator or the workflow.

1. **check**
   - reads the SHA of RubySec's `HEAD` with `git ls-remote`, without fetching
     anything;
   - downloads the published `manifest.json` (HTTP 404 means first
     deployment);
   - decides whether to regenerate:

     | Situation | Regenerate |
     | --- | --- |
     | manual run or push | yes |
     | nothing published yet | yes |
     | RubySec `HEAD` differs from the published `source_commit` | yes |
     | generator changed (`generator_digest` differs) | yes |
     | otherwise | no: `build` and `deploy` are skipped |

2. **build**: fetches *exactly* the commit read in step 1 (`git fetch
   --depth=1 <sha>`, then checks `HEAD`), even if RubySec has moved since,
   runs `scripts/export-advisories-json`, checks the output (valid gzip and
   JSON, SHA-256 matching the manifest, expected `source_commit`, at least one
   advisory) and uploads both files as the Pages artifact.
3. **deploy**: deploys the artifact with `actions/deploy-pages`.

The `generator_digest` in the manifest is a SHA-256 of
`lib/advisories_json_export.rb` and `scripts/export-advisories-json`. If a
push-triggered run fails, the next scheduled run still notices that the
generator changed and regenerates.

Safety:

- **No concurrent deployments**: every run shares the `pages` concurrency
  group. A run in progress is never cancelled; a newer pending run replaces
  an older pending one.
- **Failed generation**: `deploy` only runs when `build` succeeds. If an
  advisory has invalid YAML or the output fails a check, the run fails and
  the previously published version stays online.
- Jobs get the smallest permissions they need (`contents: read`,
  `pages: read`, then `pages: write` + `id-token: write` for the deploy only).
  Actions are pinned to commit SHAs, as in the rest of the repository.

## File format

`advisories.json.gz` is a gzip of a single-line JSON document
(about 90 KB compressed, 400 KB uncompressed, for about 1,400 advisories):

```json
{
  "schema_version": 1,
  "source_repository": "https://github.com/rubysec/ruby-advisory-db",
  "source_commit": "49bb1fbb35476f27f8cfbfcb943790633836dc1c",
  "generated_at": "2026-11-20T16:56:47Z",
  "gem_count": 484,
  "advisory_count": 1379,
  "gems": {
    "rack": [
      {
        "id": "CVE-2011-5036",
        "cve": "CVE-2011-5036",
        "ghsa": "GHSA-v6j3-7jrw-hq2p",
        "url": "https://nvd.nist.gov/vuln/detail/CVE-2011-5036",
        "title": "CVE-2011-5036 rubygem-rack: hash table collisions DoS (oCERT-2011-003)",
        "date": "2011-12-28",
        "patched_versions": ["~> 1.1.3", "~> 1.2.5", "~> 1.3.6", ">= 1.4.0"]
      }
    ],
    "activerecord-jdbc-adapter": [
      {
        "id": "GHSA-5qw5-wf2q-f538",
        "patched_versions": [">= 1.2.8"],
        "unaffected_versions": ["< 1.2.6"],
        "platform": "jruby"
      }
    ]
  }
}
```

- `gems` is keyed by gem name (the directory under `gems/`); gems and
  advisories are sorted, so two exports of the same commit only differ by
  `generated_at`.
- `id` is the advisory file name (`CVE-…`, `GHSA-…`, `OSVDB-…`), like in
  bundler-audit.
- `cve`, `ghsa`, `url`, `title`, `date`, `patched_versions`,
  `unaffected_versions` and `platform` are only present when the source
  advisory has them. Descriptions and CVSS scores are left out to keep the
  file small: follow `url` for details.
- **Version constraints are kept exactly as written in the source.** One
  entry may combine several requirements separated by commas, e.g.
  `"~> 1.2.5, >= 1.2.5.1"`. Split it on commas and pass every part to
  `Gem::Requirement`: the entry matches when *all* parts match. A version
  is vulnerable when it matches **no** entry of `patched_versions` and
  **no** entry of `unaffected_versions`. The generator rejects any
  constraint that `Gem::Requirement` cannot parse.
- `platform` (only `jruby` today) restricts an advisory to that Ruby engine.
- `schema_version` only changes when clients need to adapt.

`manifest.json` is small and pretty-printed:

```json
{
  "schema_version": 1,
  "source_repository": "https://github.com/rubysec/ruby-advisory-db",
  "source_commit": "49bb1fbb35476f27f8cfbfcb943790633836dc1c",
  "generated_at": "2026-11-20T16:56:47Z",
  "generator_digest": "689f38fb…",
  "file": "advisories.json.gz",
  "sha256": "009cc968…",
  "bytes": 90780,
  "gem_count": 484,
  "advisory_count": 1379
}
```

A client that polls can read the manifest first and only download the data
when `source_commit` or `sha256` changed.

GitHub Pages caches files for up to 10 minutes, so a new version can take a
few minutes to show up after a deployment.

## Ruby example

[`docs/examples/check_loaded_gems.rb`](examples/check_loaded_gems.rb) is a
complete, tested version. The core of it:

```ruby
require 'json'
require 'net/http'
require 'rubygems'
require 'zlib'

url  = URI('https://syadem.github.io/ruby-advisory-db/advisories.json.gz')
body = Net::HTTP.get_response(url).tap(&:value).body.b
# Pages serves the .gz as-is; only inflate if no HTTP layer already did.
json = body.start_with?("\x1f\x8b".b) ? Zlib.gunzip(body) : body
db   = JSON.parse(json)
raise 'unsupported schema' unless db['schema_version'] == 1

matches = lambda do |constraints, version|
  Array(constraints).any? do |constraint|
    Gem::Requirement.new(*constraint.split(/,\s*/)).satisfied_by?(version)
  end
end

Gem.loaded_specs.each_value do |spec|
  Array(db['gems'][spec.name]).each do |advisory|
    next if advisory['platform'] && advisory['platform'] != RUBY_ENGINE
    next if matches.(advisory['patched_versions'], spec.version)
    next if matches.(advisory['unaffected_versions'], spec.version)

    warn "#{spec.name} #{spec.version}: #{advisory['id']} #{advisory['title']} #{advisory['url']}"
  end
end
```

Run the full example against the published file or a local copy:

```bash
ruby docs/examples/check_loaded_gems.rb
```

```bash
ruby docs/examples/check_loaded_gems.rb _site/advisories.json.gz
```

It exits with status 1 when a loaded gem is vulnerable.

## Generating the file locally

The generator uses only the Ruby standard library:

```bash
ruby scripts/export-advisories-json --source . --output _site
```

`--source` is any ruby-advisory-db checkout (this one, or a RubySec clone);
the commit defaults to `git rev-parse HEAD` in that directory and can be set
with `--source-commit`. If an advisory cannot be parsed, the command prints
the file name and the problem, exits with status 1 and writes nothing:

```text
export-advisories-json: gems/broken/CVE-2099-0002.yml: invalid YAML (…)
```

Tests (fictional advisories, including a compound range, plus the client
example):

```bash
bundle exec rspec spec/advisories_json_export_spec.rb
```
