require 'minitest/autorun'
require 'json'
require 'stringio'

# Load the main script but prevent it from executing
# We'll stub ARGV to prevent argument parsing
original_argv = ARGV.dup
ARGV.clear
ARGV.push('--help')  # This will trigger help and exit

# Capture and suppress the help output and exit
begin
  old_stdout = $stdout
  $stdout = StringIO.new
  require_relative '../check_http_json'
rescue SystemExit
  # Expected - suppress the exit from --help
ensure
  $stdout = old_stdout
  ARGV.clear
  ARGV.concat(original_argv)
end

# Helper module for testing
module TestHelpers
  # Capture stdout and stderr
  def capture_output
    old_stdout = $stdout
    old_stderr = $stderr
    $stdout = StringIO.new
    $stderr = StringIO.new
    yield
    [$stdout.string, $stderr.string]
  ensure
    $stdout = old_stdout
    $stderr = old_stderr
  end

  # Reset Nagios module state between tests
  def reset_nagios
    Nagios.instance_variable_set(:@ok, nil)
    Nagios.instance_variable_set(:@warning, nil)
    Nagios.instance_variable_set(:@critical, nil)
    Nagios.instance_variable_set(:@unknown, nil)
    Nagios.instance_variable_set(:@perf, nil)
    Nagios.instance_variable_set(:@verbose, false)
    Nagios.instance_variable_set(:@output_alt_pipe, nil)
  end

  # Capture stdout and exit code from a block that calls exit
  def capture_exit
    exit_code = nil
    stdout, _ = capture_output do
      begin
        yield
      rescue SystemExit => e
        exit_code = e.status
      end
    end
    [stdout, exit_code]
  end

  # Create a minimal options hash with required keys
  # (mirrors the defaults that parse_args would set)
  def default_options
    {
      element_string: [],
      delimiter: '.'
    }
  end
end
