# frozen_string_literal: true

require_relative "lib/omniauth-cryptr/version"

Gem::Specification.new do |spec|
  spec.name = "omniauth-cryptr"
  spec.version = OmniAuth::Cryptr::VERSION
  spec.authors = ["Maxime Burriez"]
  spec.email = ["maxime@cryptr.co"]

  spec.summary = "OmniAuth OAuth2 strategy for the Cryptr platform."
  spec.description = spec.summary
  spec.homepage = 'https://github.com/cryptr-auth/omniauth-cryptr' # "TODO: Put your gem's website or public repo URL here."
  spec.license = "MIT"
  spec.required_ruby_version = ">= 2.6.0"

  # spec.metadata["allowed_push_host"] = "TODO: Set to your gem server 'https://example.com'"

  spec.metadata["homepage_uri"] = spec.homepage
  spec.metadata["source_code_uri"] = spec.homepage
  # spec.metadata["changelog_uri"] = "TODO: Put your gem's CHANGELOG.md URL here."

  # Specify which files should be added to the gem when it is released.
  # The `git ls-files -z` loads the files in the RubyGem that have been added into git.
  spec.files = Dir.chdir(File.expand_path(__dir__)) do
    `git ls-files -z`.split("\x0").reject do |f|
      (f == __FILE__) || f.match(%r{\A(?:(?:bin|test|spec|features)/|\.(?:git|travis|circleci)|appveyor)})
    end
  end
  spec.bindir = "exe"
  spec.executables = spec.files.grep(%r{\Aexe/}) { |f| File.basename(f) }
  spec.require_paths = ["lib"]

  # Uncomment to register a new dependency of your gem
  # spec.add_dependency "example-gem", "~> 1.0"

  spec.add_runtime_dependency 'omniauth', '~> 2.0'
  spec.add_runtime_dependency 'omniauth-oauth2', '~> 1.7'

  spec.add_development_dependency 'bundler'

  # For more information and examples about making a new gem, check out our
  # guide at: https://bundler.io/guides/creating_gem.html
end
