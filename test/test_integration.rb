require_relative 'test_helper'
require 'webmock/minitest'
require 'tempfile'

class TestIntegration < Minitest::Test
  include TestHelpers

  def setup
    reset_nagios
    WebMock.disable_net_connect!
  end

  def teardown
    WebMock.reset!
  end

  # Test file_target function
  def test_file_target_valid_json
    json_data = {'status' => 'ok', 'count' => 42}

    Tempfile.create(['test', '.json']) do |file|
      file.write(json_data.to_json)
      file.flush

      options = {file: file.path, v: false}
      result = file_target(options)

      assert_equal json_data, result
    end
  end

  def test_file_target_invalid_json
    Tempfile.create(['test', '.json']) do |file|
      file.write('not valid json{]')
      file.flush

      options = {file: file.path, v: false}

      stdout, exit_code = capture_exit { file_target(options) }

      assert_equal 3, exit_code
      assert_match(/UNKNOWN: Parsing JSON failed/, stdout)
    end
  end

  def test_file_target_nonexistent_file
    options = {file: '/nonexistent/file.json', v: false}

    stdout, exit_code = capture_exit { file_target(options) }

    assert_equal 2, exit_code
    assert_match(/CRIT:.*does not exist/, stdout)
  end

  # Test uri_target function with WebMock
  def test_uri_target_valid_json_response
    json_response = {'status' => 'healthy', 'uptime' => 12345}

    stub_request(:get, 'http://example.com/api/status')
      .to_return(status: 200, body: json_response.to_json, headers: {'Content-Type' => 'application/json'})

    options = {
      uri: 'http://example.com/api/status',
      timeout: 5,
      v: false
    }

    result = uri_target(options)
    assert_equal json_response, result
  end

  def test_uri_target_non_200_response
    stub_request(:get, 'http://example.com/api/status')
      .to_return(status: 404, body: 'Not Found')

    options = {
      uri: 'http://example.com/api/status',
      timeout: 5,
      status_level_default: 1,
      v: false
    }

    stdout, exit_code = capture_exit { uri_target(options) }

    assert_equal 1, exit_code
    assert_match(/WARN: Received HTTP code 404/, stdout)
  end

  def test_uri_target_custom_status_level
    stub_request(:get, 'http://example.com/api/status')
      .to_return(status: 301, body: '{}')

    options = {
      uri: 'http://example.com/api/status',
      timeout: 5,
      status_level: ['301:0'],  # Treat 301 as OK
      status_level_default: 2,
      v: false
    }

    # Should not exit since 301 is configured as level 0
    result = uri_target(options)
    assert_equal({}, result)
  end

  def test_uri_target_invalid_json_response
    stub_request(:get, 'http://example.com/api/status')
      .to_return(status: 200, body: 'this is not json')

    options = {
      uri: 'http://example.com/api/status',
      timeout: 5,
      v: false
    }

    stdout, exit_code = capture_exit { uri_target(options) }

    assert_equal 3, exit_code
    assert_match(/UNKNOWN: Parsing JSON failed/, stdout)
  end

  def test_uri_target_with_basic_auth
    json_response = {'authenticated' => true}

    stub_request(:get, 'http://example.com/api/protected')
      .with(basic_auth: ['user', 'pass'])
      .to_return(status: 200, body: json_response.to_json)

    options = {
      uri: 'http://example.com/api/protected',
      user: 'user',
      pass: 'pass',
      timeout: 5,
      v: false
    }

    result = uri_target(options)
    assert_equal json_response, result
  end

  def test_uri_target_with_custom_headers
    json_response = {'success' => true}

    stub_request(:get, 'http://example.com/api/data')
      .with(headers: {'X-Custom-Header' => 'custom-value', 'X-API-Key' => 'secret123'})
      .to_return(status: 200, body: json_response.to_json)

    options = {
      uri: 'http://example.com/api/data',
      headers: ['X-Custom-Header:custom-value', 'X-API-Key:secret123'],
      timeout: 5,
      v: false
    }

    result = uri_target(options)
    assert_equal json_response, result
  end

  def test_uri_target_https
    assert_https_uri_target_with
  end

  def test_uri_target_https_with_cacert
    assert_https_uri_target_with(cacert: '/path/to/ca.pem')
  end

  def test_uri_target_https_with_capath
    assert_https_uri_target_with(capath: '/path/to/certs/')
  end

  def test_uri_target_https_insecure_ignores_cacert
    assert_https_uri_target_with(insecure: true, cacert: '/path/to/ca.pem')
  end

  private

  def assert_https_uri_target_with(extra_options = {})
    json_response = {'secure' => true}
    stub_request(:get, 'https://secure.example.com/api/status')
      .to_return(status: 200, body: json_response.to_json)
    options = {uri: 'https://secure.example.com/api/status', timeout: 5, v: false}.merge(extra_options)
    assert_equal json_response, uri_target(options)
  end
end
