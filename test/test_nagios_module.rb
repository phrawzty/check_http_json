require_relative 'test_helper'

class TestNagiosModule < Minitest::Test
  include TestHelpers

  def setup
    reset_nagios
  end

  def test_nagios_codes_constants
    codes = Nagios.singleton_class.const_get(:CODES)
    assert_equal 'OK', codes[0]
    assert_equal 'WARN', codes[1]
    assert_equal 'CRIT', codes[2]
    assert_equal 'UNKNOWN', codes[3]
  end

  def test_msg_code_priority_critical
    Nagios.ok = 'Everything is fine'
    Nagios.warning = 'Minor issue'
    # Note: We can't test setting critical directly because it triggers do_exit
    # Instead test by setting the instance variable directly
    Nagios.instance_variable_set(:@critical, 'Major problem')

    msg, code = Nagios.msg_code
    assert_equal 'Major problem', msg
    assert_equal 2, code
  end

  def test_msg_code_priority_warning
    Nagios.ok = 'Everything is fine'
    Nagios.warning = 'Minor issue'

    msg, code = Nagios.msg_code
    assert_equal 'Minor issue', msg
    assert_equal 1, code
  end

  def test_msg_code_priority_unknown
    Nagios.ok = 'Everything is fine'
    Nagios.unknown = 'Strange state'

    msg, code = Nagios.msg_code
    assert_equal 'Strange state', msg
    assert_equal 3, code
  end

  def test_msg_code_priority_ok
    Nagios.ok = 'Everything is fine'

    msg, code = Nagios.msg_code
    assert_equal 'Everything is fine', msg
    assert_equal 0, code
  end

  def test_output_alt_pipe_substitution
    Nagios.output_alt_pipe = '!'
    Nagios.ok = 'value | with | pipes'

    stdout, _ = capture_exit { Nagios.do_exit }

    assert_match(/OK: value ! with ! pipes/, stdout)
    refute_match(/\|(?!\s)/, stdout.split(':')[1]) # No unescaped pipes after code
  end

  def test_perf_data_output
    Nagios.ok = 'Everything is fine'
    Nagios.perf = ' | metric1=100 metric2=200'

    stdout, _ = capture_exit { Nagios.do_exit }

    assert_match(/OK: Everything is fine \| metric1=100 metric2=200/, stdout)
  end

  def test_verbose_mode_forces_unknown_exit
    Nagios.verbose = true
    Nagios.ok = 'Everything is fine'

    _, exit_code = capture_exit { Nagios.do_exit }

    assert_equal 3, exit_code
  end

  def test_normal_exit_codes
    test_cases = [
      ['OK message', 0],
      ['Warning message', 1],
      ['Critical message', 2],
      ['Unknown message', 3]
    ]

    test_cases.each do |msg, expected_code|
      reset_nagios
      _, exit_code = capture_exit { Nagios.do_exit(expected_code, msg) }
      assert_equal expected_code, exit_code, "Expected exit code #{expected_code} for message '#{msg}'"
    end
  end
end
