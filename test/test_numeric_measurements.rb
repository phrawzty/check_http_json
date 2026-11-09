require_relative 'test_helper'
require 'open3'
require 'tempfile'
require 'rbconfig'

class TestNumericMeasurements < Minitest::Test
  SCRIPT = File.expand_path('../check_http_json.rb', __dir__)

  def run_check(value, warn, crit)
    Tempfile.create(['check-http-json-numeric-', '.json']) do |file|
      file.write(JSON.generate('value' => value))
      file.flush
      Open3.capture3(RbConfig.ruby, SCRIPT, '-f', file.path, '-e', 'value',
                     '-w', warn, '-c', crit)
    end
  end

  def assert_status(code, value, warn = '10', crit = '20')
    stdout, stderr, status = run_check(value, warn, crit)
    assert_equal code, status.exitstatus, stdout + stderr
  end

  def test_finite_signed_and_fractional_measurements
    [-1.5, '-1.5', 0.25, '+0.25', '.25', '1e-3', 0, '12'].each do |value|
      assert_status(0, value, '-20:20', '-30:30')
    end
  end

  def test_fractional_values_are_not_truncated
    assert_status(1, 10.5)
    assert_status(1, -10.5, '-10:10', '-20:20')
    assert_status(2, '1e3')
    assert_status(1, 12.5, '-10:10', '-20:20')
    assert_status(2, -25.5, '-10:10', '-20:20')
    assert_status(0, 10.0)
  end

  def test_large_integers_remain_exact
    [9007199254740993, '9007199254740993'].each do |value|
      assert_status(1, value, '9007199254740992', '9007199254740994')
    end
    assert_equal 9007199254740993, numeric_value('9007199254740993')
    assert_instance_of Integer, numeric_value('9007199254740993')
  end

  def test_invalid_measurements_return_unknown
    ['', '--1', '1.2.3', '.', 'NaN', 'Infinity', '1e9999',
     true, false, nil, ' 12', '12 ', '1_000'].each do |value|
      assert_status(3, value)
    end
  end

  def test_numeric_parser_accepts_supported_syntax
    assert_equal(-12, numeric_value('-12'))
    assert_equal(0.25, numeric_value('.25'))
    assert_equal(0.001, numeric_value('1e-3'))
    assert_nil numeric_value('1e9999')
    assert_nil numeric_value(nil)
  end
end
