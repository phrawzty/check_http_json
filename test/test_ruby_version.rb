require_relative 'test_helper'

class TestRubyVersion < Minitest::Test
  include TestHelpers

  def setup
    reset_nagios
  end

  %w[1.9.3 2.2.10].each do |version|
    define_method("test_unsupported_#{version.tr('.', '_')}") do
      stdout, exit_code = capture_exit { check_ruby_version(version) }

      assert_equal 3, exit_code
      assert_match(/UNKNOWN: check_http_json requires Ruby 2\.3 or later \(running #{Regexp.escape(version)}\)/, stdout)
    end
  end

  %w[2.3.0 2.10.0 3.3.5].each do |version|
    define_method("test_supported_#{version.tr('.', '_')}") do
      stdout, exit_code = capture_exit { check_ruby_version(version) }

      assert_nil exit_code
      assert_equal '', stdout
    end
  end
end
