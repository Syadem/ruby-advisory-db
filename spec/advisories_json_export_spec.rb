require 'spec_helper'
require 'fileutils'
require 'open3'
require 'tmpdir'
require_relative '../lib/advisories_json_export'
require_relative '../docs/examples/check_loaded_gems'

describe AdvisoriesJsonExport do
  let(:source_commit) { 'a' * 40 }
  let(:generated_at)  { Time.utc(2030, 1, 2, 3, 4, 5) }

  # Fictional advisories: none of these gems or identifiers are real.
  let(:advisories) do
    {
      'gems/fakegem/CVE-2099-0001.yml' => <<~YAML,
        ---
        gem: fakegem
        cve: 2099-0001
        ghsa: aaaa-bbbb-cccc
        url: https://example.com/CVE-2099-0001
        title: Fictional remote code execution
        date: 2099-01-15
        description: |
          Not a real advisory.
        cvss_v3: 9.8
        patched_versions:
          - "~> 1.2.5, >= 1.2.5.1"
          - ">= 2.0.0"
        unaffected_versions:
          - "< 1.0.0"
      YAML
      'gems/fakegem/GHSA-dddd-eeee-ffff.yml' => <<~YAML,
        ---
        gem: fakegem
        ghsa: dddd-eeee-ffff
        url: https://example.com/GHSA-dddd-eeee-ffff
        title: Fictional XSS
        date: 2099-02-01
        patched_versions:
          - ">= 3.0.0"
      YAML
      'gems/jruby-fake/OSVDB-999999.yml' => <<~YAML,
        ---
        gem: jruby-fake
        osvdb: 999999
        url: https://example.com/OSVDB-999999
        title: Fictional JRuby-only issue without a fix
        date: 2099-03-01
        platform: jruby
      YAML
      'rubies/ruby/CVE-2099-1000.yml' => <<~YAML,
        ---
        engine: ruby
        cve: 2099-1000
        url: https://example.com/CVE-2099-1000
        title: Fictional interpreter use-after-free
        date: 2099-04-01
        unaffected_versions:
          - "< 3.3.0"
        patched_versions:
          - "~> 3.3.9, >= 3.3.9"
          - ">= 3.4.2"
      YAML
      'rubies/jruby/CVE-2099-1001.yml' => <<~YAML
        ---
        engine: jruby
        cve: 2099-1001
        url: https://example.com/CVE-2099-1001
        title: Fictional JRuby issue
        date: 2099-05-01
        patched_versions:
          - ">= 9.4.9.0"
      YAML
    }
  end

  around do |example|
    Dir.mktmpdir('advisories-json-spec') do |dir|
      @tmp = dir
      example.run
    end
  end

  let(:source_dir) { File.join(@tmp, 'source') }
  let(:output_dir) { File.join(@tmp, 'out') }

  def write_advisories(files)
    files.each do |relative, content|
      path = File.join(source_dir, relative)
      FileUtils.mkdir_p(File.dirname(path))
      File.write(path, content)
    end
  end

  def generate
    described_class.generate(source_dir: source_dir,
                             output_dir: output_dir,
                             source_commit: source_commit,
                             generated_at: generated_at)
  end

  def read_output
    JSON.parse(Zlib.gunzip(File.binread(File.join(output_dir, 'advisories.json.gz'))))
  end

  before { write_advisories(advisories) }

  describe "advisories.json.gz" do
    before { generate }

    subject(:db) { read_output }

    it "is a gzip of a compact JSON document" do
      json = Zlib.gunzip(File.binread(File.join(output_dir, 'advisories.json.gz')))

      expect(json).not_to include("\n")
      expect(JSON.parse(json)).to be_a(Hash)
    end

    it "records the schema version, source commit and generation date" do
      expect(db).to include(
        'schema_version' => 1,
        'source_repository' => 'https://github.com/rubysec/ruby-advisory-db',
        'source_commit' => source_commit,
        'generated_at' => '2030-01-02T03:04:05Z',
        'gem_count' => 2,
        'advisory_count' => 3
      )
    end

    it "indexes advisories by gem name, sorted by id" do
      expect(db['gems'].keys).to eq(%w[fakegem jruby-fake])
      expect(db['gems']['fakegem'].map { |a| a['id'] })
        .to eq(%w[CVE-2099-0001 GHSA-dddd-eeee-ffff])
    end

    it "keeps the exported fields and drops the rest" do
      expect(db['gems']['fakegem'].first).to eq(
        'id' => 'CVE-2099-0001',
        'cve' => 'CVE-2099-0001',
        'ghsa' => 'GHSA-aaaa-bbbb-cccc',
        'url' => 'https://example.com/CVE-2099-0001',
        'title' => 'Fictional remote code execution',
        'date' => '2099-01-15',
        'patched_versions' => ['~> 1.2.5, >= 1.2.5.1', '>= 2.0.0'],
        'unaffected_versions' => ['< 1.0.0']
      )
    end

    it "omits fields that are absent from the source and keeps platform" do
      advisory = db['gems']['jruby-fake'].first

      expect(advisory).not_to include('patched_versions', 'unaffected_versions', 'cve', 'ghsa')
      expect(advisory['platform']).to eq('jruby')
    end

    it "preserves version constraints exactly as written" do
      expect(db['gems']['fakegem'].first['patched_versions'].first)
        .to eq('~> 1.2.5, >= 1.2.5.1')
    end

    it "indexes Ruby interpreter advisories by engine" do
      expect(db['ruby_advisory_count']).to eq(2)
      expect(db['rubies'].keys).to eq(%w[jruby ruby])
      expect(db['rubies']['ruby']).to eq([{
        'id' => 'CVE-2099-1000',
        'cve' => 'CVE-2099-1000',
        'url' => 'https://example.com/CVE-2099-1000',
        'title' => 'Fictional interpreter use-after-free',
        'date' => '2099-04-01',
        'patched_versions' => ['~> 3.3.9, >= 3.3.9', '>= 3.4.2'],
        'unaffected_versions' => ['< 3.3.0']
      }])
    end

    it "matches Ruby versions with the same rule as gems" do
      advisory = db['rubies']['ruby'].first
      vulnerable = lambda do |version|
        AdvisoryCheck.vulnerable?(advisory, Gem::Version.new(version))
      end

      expect(vulnerable.('3.2.9')).to be(false)  # unaffected
      expect(vulnerable.('3.3.3')).to be(true)
      expect(vulnerable.('3.3.9')).to be(false)  # patched in the 3.3 series
      expect(vulnerable.('3.4.1')).to be(true)
      expect(vulnerable.('3.4.2')).to be(false)
    end
  end

  it "accepts a source without rubies/" do
    FileUtils.rm_rf(File.join(source_dir, 'rubies'))
    generate

    expect(read_output).to include('rubies' => {}, 'ruby_advisory_count' => 0)
  end

  it "stops on an invalid Ruby advisory and names the file" do
    write_advisories('rubies/ruby/CVE-2099-1002.yml' => "engine: [\n")

    expect { generate }.to raise_error(%r{\Arubies/ruby/CVE-2099-1002\.yml: invalid YAML})
  end

  describe "manifest.json" do
    it "describes the published file" do
      returned = generate
      manifest = JSON.parse(File.read(File.join(output_dir, 'manifest.json')))
      gz = File.binread(File.join(output_dir, 'advisories.json.gz'))

      expect(manifest).to eq(returned)
      expect(manifest).to include(
        'schema_version' => 1,
        'source_commit' => source_commit,
        'generated_at' => '2030-01-02T03:04:05Z',
        'generator_digest' => described_class.generator_digest,
        'file' => 'advisories.json.gz',
        'sha256' => Digest::SHA256.hexdigest(gz),
        'bytes' => gz.bytesize,
        'advisory_count' => 3
      )
    end
  end

  it "is reproducible for the same input and date" do
    generate
    first = File.binread(File.join(output_dir, 'advisories.json.gz'))
    generate

    expect(File.binread(File.join(output_dir, 'advisories.json.gz'))).to eq(first)
  end

  describe "errors" do
    it "stops on invalid YAML, names the file and writes nothing" do
      write_advisories('gems/broken/CVE-2099-0002.yml' => "---\ngem: broken\ntitle: [unclosed\n")

      expect { generate }.to raise_error(
        AdvisoriesJsonExport::InvalidAdvisory,
        %r{\Agems/broken/CVE-2099-0002\.yml: invalid YAML}
      )
      expect(Dir.exist?(output_dir)).to be(false)
    end

    it "rejects a document that is not a mapping" do
      write_advisories('gems/broken/CVE-2099-0003.yml' => "--- just a string\n")

      expect { generate }.to raise_error(%r{gems/broken/CVE-2099-0003\.yml: expected a YAML mapping})
    end

    it "rejects a constraint that Gem::Requirement cannot parse" do
      write_advisories('gems/broken/CVE-2099-0004.yml' => <<~YAML)
        ---
        gem: broken
        patched_versions:
          - "> = 1.0"
      YAML

      expect { generate }.to raise_error(%r{gems/broken/CVE-2099-0004\.yml: patched_versions has an invalid constraint})
    end

    it "rejects an abbreviated source commit" do
      expect {
        described_class.generate(source_dir: source_dir, output_dir: output_dir,
                                 source_commit: 'abc1234')
      }.to raise_error(AdvisoriesJsonExport::Error, /40-character SHA/)
    end

    it "fails when no advisory is found" do
      FileUtils.rm_rf(File.join(source_dir, 'gems'))
      FileUtils.mkdir_p(File.join(source_dir, 'gems'))

      expect { generate }.to raise_error(AdvisoriesJsonExport::Error, /no advisory found/)
    end
  end

  describe "scripts/export-advisories-json" do
    let(:script) { File.join(ROOT, 'scripts', 'export-advisories-json') }

    it "generates both files" do
      out, status = Open3.capture2e(RbConfig.ruby, script, '--source', source_dir,
                                    '--output', output_dir, '--source-commit', source_commit)

      expect(status).to be_success, out
      expect(out).to include('3 advisories, 2 gems')
      expect(File.exist?(File.join(output_dir, 'manifest.json'))).to be(true)
    end

    it "exits non-zero and names the invalid file" do
      write_advisories('gems/broken/CVE-2099-0002.yml' => "gem: [\n")
      out, status = Open3.capture2e(RbConfig.ruby, script, '--source', source_dir,
                                    '--output', output_dir, '--source-commit', source_commit)

      expect(status).not_to be_success
      expect(out).to include('gems/broken/CVE-2099-0002.yml')
    end

    it "prints the generator digest" do
      out, status = Open3.capture2(RbConfig.ruby, script, '--digest')

      expect(status).to be_success
      expect(out.strip).to eq(described_class.generator_digest)
    end
  end

  describe "client example (docs/examples/check_loaded_gems.rb)" do
    before { generate }

    let(:db) { AdvisoryCheck.load(File.join(output_dir, 'advisories.json.gz')) }

    def ids_for(version, name: 'fakegem')
      spec = Gem::Specification.new { |s| s.name = name; s.version = version }
      AdvisoryCheck.vulnerable_specs(db, [spec]).map { |_, advisory| advisory['id'] }
    end

    it "evaluates the compound range '~> 1.2.5, >= 1.2.5.1' as one constraint" do
      expect(ids_for('1.2.5')).to include('CVE-2099-0001')
      expect(ids_for('1.2.5.1')).not_to include('CVE-2099-0001')
      expect(ids_for('1.2.9')).not_to include('CVE-2099-0001')
      expect(ids_for('1.3.0')).to include('CVE-2099-0001')
      expect(ids_for('2.0.0')).not_to include('CVE-2099-0001')
    end

    it "honours unaffected_versions" do
      expect(ids_for('0.9.0')).to eq(['GHSA-dddd-eeee-ffff'])
    end

    it "reports nothing for a fully patched version" do
      expect(ids_for('3.1.0')).to be_empty
    end

    it "only applies platform advisories on the matching engine" do
      expected = RUBY_ENGINE == 'jruby' ? ['OSVDB-999999'] : []

      expect(ids_for('1.0.0', name: 'jruby-fake')).to eq(expected)
    end

    it "ignores gems without advisories" do
      expect(ids_for('1.0.0', name: 'not-in-the-database')).to be_empty
    end
  end
end
