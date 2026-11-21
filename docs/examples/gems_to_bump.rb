# frozen_string_literal: true

#
# Lists the installed gems to bump, with the smallest version that fixes
# every known advisory, using a single HTTP request to GitHub Pages.
#
#   ruby docs/examples/gems_to_bump.rb [URL_OR_PATH]
#
#   activesupport 8.1.3 -> 8.1.4.1  (GHSA-2w9f-fxwj-w2qf, GHSA-8474-xrp6-wh69)
#
# Exits with status 1 when at least one gem must be bumped.
#

require 'json'
require 'net/http'
require 'rubygems'
require 'zlib'

source = ARGV.fetch(0, 'https://syadem.github.io/ruby-advisory-db/advisories.json.gz')

# The only request: the whole database (~90 KB), filtered locally.
body = if source.start_with?('http://', 'https://')
         response = Net::HTTP.get_response(URI(source))
         abort "GET #{source} failed: HTTP #{response.code}" unless response.is_a?(Net::HTTPSuccess)
         response.body.b
       else
         File.binread(source)
       end
db = JSON.parse(body.start_with?("\x1f\x8b".b) ? Zlib.gunzip(body) : body)
abort "Unsupported schema_version #{db['schema_version']}" unless db['schema_version'] == 1

# "~> 8.0.5, >= 8.0.5.2" is one constraint: every part must match.
requirements = ->(constraints) { Array(constraints).map { |c| Gem::Requirement.new(*c.split(/,\s*/)) } }

vulnerable = lambda do |advisory, version|
  (requirements.(advisory['patched_versions']) + requirements.(advisory['unaffected_versions']))
    .none? { |req| req.satisfied_by?(version) }
end

# Candidate fixed versions are the lower bounds written in patched_versions
# (">= 8.1.4.1", "~> 1.2.5"...). The target is the smallest candidate above
# the installed version that no advisory of the gem flags.
target_version = lambda do |advisories, current|
  advisories.flat_map { |a| requirements.(a['patched_versions']) }
            .flat_map(&:requirements)
            .filter_map { |op, version| version if ['>=', '~>', '='].include?(op) }
            .uniq.sort
            .select { |version| version > current }
            .find { |version| advisories.none? { |a| vulnerable.(a, version) } }
end

bumps = Gem::Specification.map { |spec| [spec.name, spec.version] }.uniq.sort.filter_map do |name, version|
  advisories = Array(db['gems'][name]).select { |a| a['platform'].nil? || a['platform'] == RUBY_ENGINE }
  hits = advisories.select { |a| vulnerable.(a, version) }
  next if hits.empty?

  [name, version, target_version.(advisories, version), hits.map { |a| a['id'] }]
end

warn "RubySec #{db['source_commit'][0, 12]} (#{db['generated_at']})"
bumps.each do |name, version, target, ids|
  puts format('%-30s %s -> %s  (%s)', name, version, target || 'no fixed version known', ids.join(', '))
end
warn bumps.empty? ? 'Nothing to bump.' : "#{bumps.size} gem version(s) to bump."
exit(bumps.empty? ? 0 : 1)
