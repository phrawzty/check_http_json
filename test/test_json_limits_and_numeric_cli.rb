require_relative 'test_helper'
require 'open3'
require 'tempfile'
require 'rbconfig'
require 'webmock/minitest'

class TestJsonLimitsAndNumericCli < Minitest::Test
  include TestHelpers

  SCRIPT = File.expand_path('../check_http_json.rb', __dir__)

  def setup
    reset_nagios
  end

  def teardown
    WebMock.reset!
  end

  def run_cli(payload, *args)
    Tempfile.create(['check-http-json-', '.json']) do |file|
      file.write(JSON.generate(payload))
      file.flush
      Open3.capture3(RbConfig.ruby, SCRIPT, '-f', file.path, '-e', 'value', *args)
    end
  end

  def assert_cli_code(expected, payload, *args)
    stdout, stderr, status = run_cli(payload, *args)
    assert_equal expected, status.exitstatus, stdout + stderr
    [stdout, stderr]
  end

  def test_negative_decimal_and_exponent_values_reach_threshold_checks
    [-1.5, '-1.5', 0.25, '+0.25', '.25', '1e-3', 0, '12'].each do |value|
      assert_cli_code(0, {'value' => value}, '--warn', '-20:20', '--crit', '-30:30')
    end
    assert_cli_code(1, {'value' => 10.5}, '--warn', '10', '--crit', '20')
    assert_cli_code(1, {'value' => -10.5}, '--warn', '-10:10', '--crit', '-20:20')
    assert_cli_code(2, {'value' => '1e3'}, '--warn', '10', '--crit', '20')
    assert_cli_code(1, {'value' => 12.5}, '--warn', '-10:10', '--crit', '-20:20')
    assert_cli_code(2, {'value' => -25.5}, '--warn', '-10:10', '--crit', '-20:20')
  end

  def test_invalid_or_nonfinite_values_are_unknown
    ['', '--1', '1.2.3', '.', 'NaN', 'Infinity', '1e9999', true, nil].each do |value|
      assert_cli_code(3, {'value' => value}, '--warn', '10', '--crit', '20')
    end
  end

  def test_node_limit_accepts_exact_boundary_and_rejects_next_node
    payload = {'value' => 'ok', 'extra' => [1, 2, 3]}
    assert_cli_code(0, payload, '--result', 'ok', '--max_json_elements', '6')
    stdout, = assert_cli_code(3, payload, '--result', 'ok', '--max_json_elements', '5')
    assert_includes stdout, 'JSON contains more than 5 elements'
  end

  def test_file_parser_respects_configurable_depth_limit
    payload = {'value' => 'ok', 'extra' => {'nested' => {'deep' => 1}}}
    stdout, = assert_cli_code(3, payload, '--result', 'ok', '--max_json_depth', '2')
    assert_includes stdout, 'Parsing JSON failed'
    assert_cli_code(0, payload, '--result', 'ok', '--max_json_depth', '4')
  end

  def test_http_parser_respects_depth_limit
    WebMock.disable_net_connect!
    stub_request(:get, 'http://example.com/limits')
      .to_return(status: 200, body: '{"a":{"b":{"c":1}}}')
    options = default_options.merge(uri: 'http://example.com/limits', timeout: 5,
                                    v: false, max_json_depth: 2)
    stdout, exit_code = capture_exit { uri_target(options) }
    assert_equal 3, exit_code
    assert_includes stdout, 'Parsing JSON failed'
  end

  def test_flattener_direct_call_has_limits_without_cli_options
    limits = {max_depth: 1, max_elements: 100, elements: 0}
    assert_raises(JsonComplexityExceeded) do
      hash_flatten({'a' => {'b' => 1}}, '.', nil, {}, 0, limits)
    end
    limits = {max_depth: 10, max_elements: 2, elements: 0}
    assert_equal({'a' => 1}, hash_flatten({'a' => 1}, '.', nil, {}, 0, limits))
    assert_equal({'a' => 1}, hash_flatten({'a' => 1}, '.'))
  end

  def test_invalid_complexity_limits_are_unknown
    ['--max_json_depth', '--max_json_elements'].each do |flag|
      ['0', '-1'].each do |value|
        stdout, = assert_cli_code(3, {'value' => 'ok'}, '--result', 'ok', flag, value)
        assert_includes stdout, 'must be greater than zero'
      end
    end
  end

  def test_long_output_is_preserved
    stdout, = assert_cli_code(0, {'value' => 'ok', 'detail' => 'extra detail'},
                              '--result', 'ok', '--long_output', 'detail')
    assert_equal 'extra detail', stdout.lines[1].strip
  end
end
