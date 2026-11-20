# frozen_string_literal: true

#
# Checks the gems loaded in the current process against advisories.json.gz,
# using only the Ruby standard library (no Bundler, no bundler-audit, no
# YAML).
#
#   ruby docs/examples/check_loaded_gems.rb [URL_OR_PATH]
#
# Or, from inside an application:
#
#   require_relative 'check_loaded_gems'
#   db = AdvisoryCheck.load(AdvisoryCheck::DEFAULT_URL)
#   AdvisoryCheck.vulnerable_specs(db).each { |spec, advisory| ... }
#

require 'json'
require 'net/http'
require 'rubygems'
require 'uri'
require 'zlib'

module AdvisoryCheck
  DEFAULT_URL = 'https://syadem.github.io/ruby-advisory-db/advisories.json.gz'
  SUPPORTED_SCHEMA = 1

  # Reads the file from a URL or a local path and returns the parsed JSON.
  def self.load(location)
    body = if location.start_with?('https://', 'http://')
             fetch(URI(location))
           else
             File.binread(location)
           end
    # GitHub Pages serves the .gz as-is; inflate unless an HTTP layer
    # already did.
    json = body.start_with?("\x1f\x8b".b) ? Zlib.gunzip(body) : body
    db = JSON.parse(json)

    unless db['schema_version'] == SUPPORTED_SCHEMA
      raise "unsupported schema_version #{db['schema_version'].inspect}"
    end

    db
  end

  def self.fetch(uri, redirects = 3)
    response = Net::HTTP.get_response(uri)
    case response
    when Net::HTTPSuccess then response.body.b
    when Net::HTTPRedirection
      raise 'too many redirects' if redirects.zero?

      fetch(URI.join(uri, response['location']), redirects - 1)
    else
      raise "GET #{uri} failed: #{response.code}"
    end
  end

  # "~> 1.2.5, >= 1.2.5.1" is one constraint made of two requirements.
  def self.requirement(constraint)
    Gem::Requirement.new(*constraint.split(/,\s*/))
  end

  def self.matches_any?(constraints, version)
    Array(constraints).any? { |c| requirement(c).satisfied_by?(version) }
  end

  # Same rule as bundler-audit: vulnerable unless patched or unaffected.
  def self.vulnerable?(advisory, version)
    !matches_any?(advisory['patched_versions'], version) &&
      !matches_any?(advisory['unaffected_versions'], version)
  end

  # Advisories with a platform (e.g. "jruby") only apply on that engine.
  def self.applies_to_platform?(advisory)
    platform = advisory['platform']
    platform.nil? || platform == RUBY_ENGINE
  end

  # Returns [[Gem::Specification, advisory Hash], ...].
  def self.vulnerable_specs(db, specs = Gem.loaded_specs.values)
    specs.flat_map do |spec|
      Array(db['gems'][spec.name]).filter_map do |advisory|
        next unless applies_to_platform?(advisory)

        [spec, advisory] if vulnerable?(advisory, spec.version)
      end
    end
  end
end

if $PROGRAM_NAME == __FILE__
  db = AdvisoryCheck.load(ARGV.fetch(0, AdvisoryCheck::DEFAULT_URL))
  findings = AdvisoryCheck.vulnerable_specs(db)

  puts "Advisory database #{db['source_commit'][0, 12]} (#{db['generated_at']})"
  findings.each do |spec, advisory|
    puts "#{spec.name} #{spec.version}: #{advisory['id']} #{advisory['title']}"
    puts "  #{advisory['url']}" if advisory['url']
    puts "  patched: #{advisory['patched_versions'].join(' | ')}" if advisory['patched_versions']
  end
  puts findings.empty? ? 'No vulnerable gem loaded.' : "#{findings.size} advisory(ies) found."
  exit(findings.empty? ? 0 : 1)
end
