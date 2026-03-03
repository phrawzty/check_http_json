require_relative 'test_helper'

class TestSanityCheck < Minitest::Test
  include TestHelpers

  def setup
    reset_nagios
  end

  def test_sanity_check_missing_target
    options = default_options
    # Intentionally not setting :uri or :file

    stdout, exit_code = capture_exit { sanity_check(options) }

    assert_equal 3, exit_code
    assert_match(/Must specify target URI or file/, stdout)
  end

  def test_sanity_check_both_uri_and_file
    options = default_options.merge({
      uri: 'http://example.com',
      file: '/tmp/test.json',
      element_string: ['test']
    })

    stdout, exit_code = capture_exit { sanity_check(options) }

    assert_equal 3, exit_code
    assert_match(/Must specify either target URI or file, but not both/, stdout)
  end

  def test_sanity_check_missing_element
    options = default_options.merge({
      uri: 'http://example.com'
    })

    stdout, exit_code = capture_exit { sanity_check(options) }

    assert_equal 3, exit_code
    assert_match(/Must specify a desired element/, stdout)
  end

  def test_sanity_check_both_element_types
    options = default_options.merge({
      uri: 'http://example.com',
      element_string: ['test'],
      element_regex: 'test.*'
    })

    stdout, exit_code = capture_exit { sanity_check(options) }

    assert_equal 3, exit_code
    assert_match(/Must specify either an element string OR an element regular expression/, stdout)
  end

  def test_sanity_check_missing_thresholds
    options = default_options.merge({
      uri: 'http://example.com',
      element_string: ['test']
    })

    stdout, exit_code = capture_exit { sanity_check(options) }

    assert_equal 3, exit_code
    assert_match(/Must specify an expected result OR the warn and crit thresholds/, stdout)
  end

  def test_sanity_check_delimiter_too_long
    options = default_options.merge({
      uri: 'http://example.com',
      element_string: ['test'],
      delimiter: '...',
      warn: '10',
      crit: '20'
    })

    stdout, exit_code = capture_exit { sanity_check(options) }

    assert_equal 3, exit_code
    assert_match(/Delimiter must be a single character/, stdout)
  end

  def test_sanity_check_incomplete_basic_auth
    options = default_options.merge({
      uri: 'http://example.com',
      element_string: ['test'],
      warn: '10',
      crit: '20',
      user: 'testuser'
      # Missing password
    })

    stdout, exit_code = capture_exit { sanity_check(options) }

    assert_equal 3, exit_code
    assert_match(/Must specify both a username and a password/, stdout)
  end

  def test_sanity_check_incomplete_client_cert
    options = default_options.merge({
      uri: 'https://example.com',
      element_string: ['test'],
      warn: '10',
      crit: '20',
      cert: '/path/to/cert.pem'
      # Missing key
    })

    stdout, exit_code = capture_exit { sanity_check(options) }

    assert_equal 3, exit_code
    assert_match(/Both --cert and --key must be specified together/, stdout)
  end

  def test_sanity_check_valid_config_with_thresholds
    options = default_options.merge({
      uri: 'http://example.com',
      element_string: ['test'],
      warn: '10',
      crit: '20',
      v: false
    })

    # Should not raise or exit
    assert_silent do
      sanity_check(options)
    end
  end

  def test_sanity_check_valid_config_with_result_string
    options = default_options.merge({
      uri: 'http://example.com',
      element_string: ['test'],
      result_string: 'expected_value',
      v: false
    })

    # Should not raise or exit
    assert_silent do
      sanity_check(options)
    end
  end
end
