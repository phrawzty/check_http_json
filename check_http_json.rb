#!/usr/bin/ruby1.9.1

# Name: check_http_json.rb
# Author: Daniel Maher
# Description: Nagios plugin that makes an HTTP connection and looks for some JSON or summat.


# Requires
require 'rubygems'
require 'json'
require 'net/http'
require 'uri'
require 'optparse'
require 'timeout'

# Globals
@options = {}


# Some handy defs.

# Display verbose output (if being run by a human for example).
def say msg
    if @options[:verbose] == true
        puts msg
    end
end

# Manage the exit code explicitly.
def do_exit code
    if @options[:verbose] == true
        exit 3
    else
        exit code
    end
end

# As the results may be nested hashes; flatten that out into something manageable. (pyr magic)
def hash_flatten(hash, prefix=nil)
    hash.map{|key,val|
        newkey = key
        newkey = '%s.%s' % [prefix, key] if prefix
        if val.is_a? Hash
            hash_flatten val, newkey
        else
            {newkey => val}
        end
    }.compact.reduce{|e1, e2| e1.merge e2}
end

# Parse the nutty Nagios range syntax.
# http://nagiosplug.sourceforge.net/developer-guidelines.html#THRESHOLDFORMAT
def nutty_parse(thresh, want, got)
    retval = 'FAIL'
 
    # if there is a non-numeric character we have to deal with that
    # got < want
    if want =~ /^(\d+):$/ then
        if got.to_i < $1.to_i then
            retval = 'KO'
        else
            retval = 'OK'
        end
    end

    # got > want
    if want =~ /^~:(\d+)$/ then
        if got.to_i > $1.to_i then
            retval = 'KO'
        else
            retval = 'OK'
        end
    end

    # outside specific range
    if want =~ /^(\d+):(\d+)$/ then
        if got.to_i < $1.to_i or got.to_i > $2.to_i then
            retval = 'KO'
        else
            retval = 'OK'
        end
    end

    # inside specific range
    if want =~ /^@(\d+):(\d+)$/ then
        if got.to_i >= $1.to_i and got.to_i <= $2.to_i then
            retval = 'KO'
        else
            retval = 'OK'
        end
    end

    # otherwise general range
    if not want =~ /\D/ then
        if got.to_i < 0 or got.to_i > want.to_i then
            retval = 'KO'
        else
            retval = 'OK'
        end
    end

    if retval == 'OK' then
        say('%s threshold not exceeded.' % [thresh])
    elsif retval == 'KO' then
        say('%s threshold exceeded.' % [thresh])
    else
        say('"%s" is a strange and confusing %s value.' % [want, thresh])
    end

    return retval
end


# And now for some runtime.

# Parse cli args
optparse = OptionParser.new do |opts|
    opts.banner = 'Usage: %s -u <URI> -e <element> -w <warn> -c <crit>' % [$0]

    opts.on('-h', '--help', 'Help info') do
        puts opts
        do_exit(3)
    end

    @options[:verbose] = false
    opts.on('-v', '--verbose', 'Human output') do
        @options[:verbose] = true
    end

    @options[:uri] = nil
    opts.on('-u', '--uri URI', 'Target URI') do |uri|
        @options[:uri] = uri
    end

    @options[:element] = nil
    opts.on('-e', '--element ELEMENT', 'Desired element (ex. foo=>bar=>ish is foo.bar.ish)') do |element|
        @options[:element] = element
    end

    @options[:result] = nil
    opts.on('-r', '--result STRING', 'Expected (string) result. No need for -w or -c.') do |result|
        @options[:result] = result
    end

    @options[:warn] = nil
    opts.on('-w', '--warn VALUE', 'Warning threshold') do |warn|
        @options[:warn] = warn.to_s
    end

    @options[:crit] = nil
    opts.on('-c', '--crit VALUE', 'Critical threshold') do |crit|
        @options[:crit] = crit.to_s
    end

    @options[:timeout] = 5
    opts.on('-t', '--timeout SECONDS', 'Wait before HTTP timeout') do |timeout|
        @options[:timeout] = timeout.to_i
    end

end

# Choose your arguments wisely.
optparse.parse!

# In life, some arguments cannot be avoided.
error_msg = []

if not @options[:uri] then
    error_msg.push('Need to specify the URI.')
end
if not @options[:element] then
    error_msg.push('Need to specify a desired element.')
end
if not (@options[:result] or (@options[:warn] and @options[:crit])) then
    error_msg.push('Need to specify an expected result OR the warn and crit thresholds.')
end

if error_msg.count > 0 then
    puts 'Aborting for the following reason(s):'
    error_msg.each do |msg|
        puts msg
    end
    puts '"%s --help" for more information.' % [$0]
    do_exit(3)
end

# Ok, let's go.
uri = URI.parse(@options[:uri])
http = Net::HTTP.new(uri.host, uri.port)

# Timeout handler, just in case.
response = nil
begin
    Timeout::timeout(@options[:timeout]) do
        request = Net::HTTP::Get.new(uri.request_uri)
        response = http.request(request)
    end
rescue Timeout::Error
    say('The HTTP connection timed out after %i seconds.' % [@options[:timeout]])
    puts 'CRIT: Connection timed out.'
    do_exit(2)
end

# We must get a proper response.
if not response.code.to_i == 200 then
    puts 'WARN: Received HTTP code %s instead of 200.' % [response.code]
    do_exit(1)
end

say("\nRESPONSE:\n---\n%s\n---" % [response.body])

# Make a JSON object from the response.
json = JSON.parse response.body

# Flatten that bad boy.
json_flat = hash_flatten(json)

# Look for the element, and don't freak out if it's not there.
if not json_flat[@options[:element]] then
    puts 'WARN: %s not found in response.' % [@options[:element]]
    do_exit(1)
end

say('The value of %s is: %s' % [@options[:element], json_flat[@options[:element]]])

# If we're looking for a string...
if @options[:result] then
    if json_flat[@options[:element]].to_s == @options[:result].to_s then
        puts 'OK: %s is %s' % [@options[:element], json_flat[@options[:element]]]
        do_exit(0)
    else
        puts 'CRIT: %s is %s' % [@options[:element], json_flat[@options[:element]]]
        do_exit(2)
    end
end

# If we're dealing with threshold values...

# Numbahs only, brah.
if json_flat[@options[:element]] =~ /\D/ then
    say('The value of %s contains non-numeric characters.' % [@options[:element]])
    puts 'UNKNOWN: Return value syntax failure.'
    do_exit(3)
end

if @options[:warn] then
    warn = 'FAIL'
    warn = nutty_parse('Warning', @options[:warn], json_flat[@options[:element]])
    if warn == 'FAIL'
        puts 'UNKNOWN: Warn threshold syntax failure.'
        do_exit(3)
    end
end

if @options[:crit] then
    crit = 'FAIL'
    crit = nutty_parse('Critical', @options[:crit], json_flat[@options[:element]])
    if crit == 'FAIL'
        puts 'UNKNOWN: Critical threshold syntax failure.'
        do_exit(3)
    end
end

# Assemble the message.
msg = 'OK: '
exit_code = 0

if warn == 'KO' then
    msg = 'WARN: '
    exit_code = 1
end

if crit == 'KO' then
    msg = 'CRIT: '
    exit_code = 2
end

msg << '%s is %s' % [@options[:element], json_flat[@options[:element]]]

# Finally output the message and exit.
puts msg
do_exit(exit_code)
