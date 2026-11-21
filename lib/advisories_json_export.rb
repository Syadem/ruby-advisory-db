# frozen_string_literal: true

require 'date'
require 'digest'
require 'json'
require 'rubygems'
require 'stringio'
require 'time'
require 'yaml'
require 'zlib'

#
# Builds a compact, gzipped JSON index of the advisories found in a checkout
# of the ruby-advisory-db repository: gem advisories under `gems/` (indexed
# by gem name) and Ruby interpreter advisories under `rubies/` (indexed by
# engine: ruby, jruby...).
#
# The output lets a Ruby program check its gems and its Ruby version against
# known advisories with nothing but the standard library (Zlib + JSON +
# Gem::Requirement): no Bundler, no bundler-audit, no YAML parsing and no
# clone of the source repository.
#
# Only the Ruby standard library is used, so the generator runs without
# `bundle install`.
#
module AdvisoriesJsonExport
  # Bump when the structure of advisories.json changes in a way clients
  # must know about.
  SCHEMA_VERSION = 1

  DATA_FILE     = 'advisories.json.gz'
  MANIFEST_FILE = 'manifest.json'

  DEFAULT_SOURCE_REPOSITORY = 'https://github.com/rubysec/ruby-advisory-db'

  # Files whose content defines the output. Their digest is published in the
  # manifest so the workflow regenerates when the generator changes.
  GENERATOR_FILES = [
    __FILE__,
    File.expand_path('../scripts/export-advisories-json', __dir__)
  ].freeze

  class Error < StandardError; end

  # Raised for a single advisory file that cannot be exported. The message
  # always starts with the file path relative to the source directory.
  class InvalidAdvisory < Error
    attr_reader :path

    def initialize(path, message)
      @path = path
      super("#{path}: #{message}")
    end
  end

  VERSION_FIELDS = %w[patched_versions unaffected_versions].freeze

  def self.generator_digest
    digest = Digest::SHA256.new
    GENERATOR_FILES.each do |file|
      digest << File.basename(file) << "\0" << File.binread(file) << "\0"
    end
    digest.hexdigest
  end

  #
  # Reads `<source_dir>/gems/*/*.yml` (required) and
  # `<source_dir>/rubies/*/*.yml` (optional), and writes `advisories.json.gz` and
  # `manifest.json` into `output_dir`. Returns the manifest as a Hash.
  #
  # Raises InvalidAdvisory (naming the file) as soon as one advisory cannot
  # be parsed, and Error when no advisory is found at all; nothing is
  # written in either case.
  #
  def self.generate(source_dir:, output_dir:, source_commit:,
                    source_repository: DEFAULT_SOURCE_REPOSITORY,
                    generated_at: Time.now.utc)
    Generator.new(source_dir: source_dir,
                  source_commit: source_commit,
                  source_repository: source_repository,
                  generated_at: generated_at).write(output_dir)
  end

  class Generator
    SHA_PATTERN = /\A[0-9a-f]{40}\z/

    def initialize(source_dir:, source_commit:, source_repository:, generated_at:)
      unless source_commit.to_s.match?(SHA_PATTERN)
        raise Error, "source commit must be a full 40-character SHA, got #{source_commit.inspect}"
      end

      @source_dir        = File.expand_path(source_dir)
      @source_commit     = source_commit
      @source_repository = source_repository
      @generated_at      = generated_at.utc
    end

    def document
      gems   = collect('gems', required: true)
      rubies = collect('rubies', required: false)

      {
        'schema_version'       => SCHEMA_VERSION,
        'source_repository'    => @source_repository,
        'source_commit'        => @source_commit,
        'generated_at'         => @generated_at.iso8601,
        'gem_count'            => gems.size,
        'advisory_count'       => gems.sum { |_, list| list.size },
        'ruby_advisory_count'  => rubies.sum { |_, list| list.size },
        'gems'                 => gems,
        'rubies'               => rubies
      }
    end

    def write(output_dir)
      doc  = document
      gzip = gzip(JSON.generate(doc))

      manifest = {
        'schema_version'    => SCHEMA_VERSION,
        'source_repository' => @source_repository,
        'source_commit'     => @source_commit,
        'generated_at'      => doc['generated_at'],
        'generator_digest'  => AdvisoriesJsonExport.generator_digest,
        'file'              => DATA_FILE,
        'sha256'            => Digest::SHA256.hexdigest(gzip),
        'bytes'             => gzip.bytesize,
        'gem_count'         => doc['gem_count'],
        'advisory_count'    => doc['advisory_count'],
        'ruby_advisory_count' => doc['ruby_advisory_count']
      }

      Dir.mkdir(output_dir) unless Dir.exist?(output_dir)
      atomic_write(File.join(output_dir, DATA_FILE), gzip)
      atomic_write(File.join(output_dir, MANIFEST_FILE),
                   JSON.pretty_generate(manifest) + "\n")
      manifest
    end

    private

    #
    # Reads `<dir>/<name>/*.yml` and indexes the advisories by <name>: the gem
    # name under gems/, the Ruby engine (ruby, jruby...) under rubies/.
    #
    def collect(dir, required:)
      base = File.join(@source_dir, dir)
      unless File.directory?(base)
        raise Error, "no #{dir}/ directory in #{@source_dir}" if required

        return {}
      end

      paths = Dir.glob('*/*.yml', base: base).sort
      raise Error, "no advisory found under #{base}" if paths.empty? && required

      index = Hash.new { |hash, name| hash[name] = [] }
      paths.each do |relative|
        name = File.dirname(relative)
        index[name] << load_advisory(File.join(dir, relative))
      end

      index.sort.to_h { |name, list| [name, list.sort_by { |a| a['id'] }] }
    end

    def load_advisory(relative_path)
      data = parse_yaml(relative_path)
      unless data.is_a?(Hash)
        raise InvalidAdvisory.new(relative_path, 'expected a YAML mapping at the top level')
      end

      advisory = { 'id' => File.basename(relative_path, '.yml') }
      advisory['cve']   = "CVE-#{data['cve']}"   if present?(data['cve'])
      advisory['ghsa']  = "GHSA-#{data['ghsa']}" if present?(data['ghsa'])
      advisory['url']   = string_field(relative_path, data, 'url')   if present?(data['url'])
      advisory['title'] = string_field(relative_path, data, 'title') if present?(data['title'])
      advisory['date']  = date_field(data['date']) if present?(data['date'])

      VERSION_FIELDS.each do |field|
        next unless present?(data[field])

        advisory[field] = version_constraints(relative_path, field, data[field])
      end

      if present?(data['platform'])
        advisory['platform'] = string_field(relative_path, data, 'platform')
      end

      advisory
    end

    def parse_yaml(relative_path)
      YAML.safe_load_file(File.join(@source_dir, relative_path),
                          permitted_classes: [Date])
    rescue Psych::Exception => e
      # Psych::SyntaxError, Psych::DisallowedClass, Psych::AliasesNotEnabled…
      raise InvalidAdvisory.new(relative_path, "invalid YAML (#{e.message})")
    end

    #
    # Constraints are kept exactly as written in the source ("~> 1.2.5, >=
    # 1.2.5.1" stays one string). Each one is still checked with
    # Gem::Requirement so that clients never receive a constraint they
    # cannot parse.
    #
    def version_constraints(relative_path, field, value)
      unless value.is_a?(Array) && value.all? { |v| v.is_a?(String) }
        raise InvalidAdvisory.new(relative_path, "#{field} must be a list of strings")
      end

      value.each do |constraint|
        Gem::Requirement.new(*constraint.split(/,\s*/))
      rescue Gem::Requirement::BadRequirementError, ArgumentError => e
        raise InvalidAdvisory.new(relative_path,
                                  "#{field} has an invalid constraint #{constraint.inspect} (#{e.message})")
      end

      value
    end

    def string_field(relative_path, data, field)
      value = data[field]
      return value if value.is_a?(String)

      raise InvalidAdvisory.new(relative_path, "#{field} must be a string")
    end

    def date_field(value)
      value.respond_to?(:iso8601) ? value.iso8601 : value.to_s
    end

    def present?(value)
      !(value.nil? || (value.respond_to?(:empty?) && value.empty?))
    end

    def gzip(json)
      io = StringIO.new(+'', 'wb')
      gz = Zlib::GzipWriter.new(io, Zlib::BEST_COMPRESSION)
      gz.mtime = @generated_at
      gz.write(json)
      gz.close
      io.string
    end

    def atomic_write(path, content)
      tmp = "#{path}.tmp-#{Process.pid}"
      File.binwrite(tmp, content)
      File.rename(tmp, path)
    ensure
      File.unlink(tmp) if tmp && File.exist?(tmp)
    end
  end
end
