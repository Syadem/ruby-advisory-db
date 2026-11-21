# frozen_string_literal: true

#
# Checks every installed gem (Gem::Specification.each) against the RubySec
# advisories published on GitHub Pages. Standard library only.
#
#   ruby docs/examples/check_installed_gems.rb [URL_OR_PATH]
#
# Exits with status 1 when at least one installed gem is vulnerable.
#

require 'json'
require 'net/http'
require 'rubygems'
require 'zlib'

source = ARGV.fetch(0, 'https://syadem.github.io/ruby-advisory-db/advisories.json.gz')

body = if source.start_with?('http://', 'https://')
         response = Net::HTTP.get_response(URI(source))
         abort "GET #{source} failed: HTTP #{response.code}" unless response.is_a?(Net::HTTPSuccess)
         response.body.b
       else
         File.binread(source)
       end
db = JSON.parse(body.start_with?("\x1f\x8b".b) ? Zlib.gunzip(body) : body)
abort "Unsupported schema_version #{db['schema_version']}" unless db['schema_version'] == 1

# "~> 1.2.5, >= 1.2.5.1" is a single constraint: every part must match.
matches_any = lambda do |constraints, version|
  Array(constraints).any? do |constraint|
    Gem::Requirement.new(*constraint.split(/,\s*/)).satisfied_by?(version)
  end
end

checked  = 0
findings = []

Gem::Specification.each do |spec|
  checked += 1

  Array(db['gems'][spec.name]).each do |advisory|
    next if advisory['platform'] && advisory['platform'] != RUBY_ENGINE
    next if matches_any.(advisory['patched_versions'], spec.version)
    next if matches_any.(advisory['unaffected_versions'], spec.version)

    findings << [spec, advisory]
  end
end

puts "RubySec #{db['source_commit'][0, 12]} (#{db['generated_at']}), " \
     "#{checked} installed gem versions checked"

by_spec = findings.group_by(&:first).sort_by { |spec, _| [spec.name, spec.version] }

by_spec.each do |spec, pairs|
  puts
  puts "#{spec.name} #{spec.version}#{' (default gem)' if spec.default_gem?}"
  pairs.map(&:last).sort_by { |a| a['id'] }.each do |advisory|
    fix = Array(advisory['patched_versions']).join(' | ')
    puts "  #{advisory['id']}: #{advisory['title']}"
    puts "    #{advisory['url']}" if advisory['url']
    puts "    fix: #{fix.empty? ? 'none' : fix}"
  end
end

puts
puts findings.empty? ? 'No vulnerable gem installed.' : "#{by_spec.size} vulnerable gem version(s), #{findings.size} advisory(ies)."
exit(findings.empty? ? 0 : 1)
