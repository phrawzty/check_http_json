#!/usr/bin/env ruby

# Name: check_http_json.rb
# Author: https://github.com/phrawzty/check_http_json/commits/master
# Description: Nagios plugin that makes an HTTP connection and parses the JSON result.
#
# Copyright 2012 Daniel Maher
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.



# Requires.
require 'rubygems'
require 'json'
require 'net/http'
require 'net/https'
require 'uri'
require 'optparse'
require 'timeout'



# Herp derp.
options = {}



# Def jam.

# Display verbose output (if being run by a human for example).
def say (v, msg)
    if v == true
        puts '+ %s' % [msg]
    end
end

# Output one-liner and manage the exit code explicitly.
def do_exit (v, code, msg)
    puts msg unless msg == nil
    if v == true
        exit 3
    else
        exit code
    end
end

# The results may be nested hashes; flatten that out into something manageable.
def hash_flatten(hash, delimiter, prefix = nil, flat = {})
    if hash.is_a? Array then
        hash.each_index do |index|
            newkey = index
            newkey = '%s%s%s' % [prefix, delimiter, newkey] if prefix
            val = hash[index]
            hash_flatten val, delimiter, newkey, flat
        end
    elsif hash.is_a? Hash then
        hash.keys.each do |key|
            newkey = key
            newkey = '%s%s%s' % [prefix, delimiter, key] if prefix
            val = hash[key]
            hash_flatten val, delimiter, newkey, flat
        end
    else
        flat[prefix] = hash
    end

    return flat
end

# Parse the nutty Nagios range syntax.
# http://nagiosplug.sourceforge.net/developer-guidelines.html#THRESHOLDFORMAT
def nutty_parse(thresh, want, got, v, element)
    retval = 'FAIL'
 
    # if there is a non-numeric character we have to deal with that
    # got < want
    if want =~ /^(\d+):$/ then
        if got.to_i < $1.to_i then
            retval = '%s is below threshold value %s (%s)' % [element, $1, got]
        else
            retval = 'OK'
        end
    end

    # got > want
    if want =~ /^~:(\d+)$/ then
        if got.to_i > $1.to_i then
            retval = '%s is above threshold value %s (%s)' % [element, $1, got]
        else
            retval = 'OK'
        end
    end

    # outside specific range
    if want =~ /^(\d+):(\d+)$/ then
        if got.to_i < $1.to_i or got.to_i > $2.to_i then
            retval = '%s is outside expected range [%s:%s] (%s)' % [element, $1, $2, got] 
        else
            retval = 'OK'
        end
    end

    # inside specific range
    if want =~ /^@(\d+):(\d+)$/ then
        if got.to_i >= $1.to_i and got.to_i <= $2.to_i then
            retval = '%s is in  value range [%s:%s] (%s)' % [element, $1, $2, got]
        else
            retval = 'OK'
        end
    end

    # otherwise general range
    if not want =~ /\D/ then
        if got.to_i > want.to_i then
            retval = '%s is above threshold value %s (%s)' % [element, want, got]
        elsif got.to_i < 0  then
            retval = '%s is below 0 (%s)' % [element, got]
        else
            retval = 'OK'
        end
    end

    if retval == 'OK' then
        say(v, '%s threshold not exceeded.' % [thresh])
    elsif retval == 'KO' then
        say(v, '%s threshold exceeded.' % [thresh])
    else
        say(v, '"%s" is a strange and confusing %s value.' % [want, thresh])
    end

    return retval
end

# Deal with a URI target.
def uri_target(options)
    uri = URI.parse(options[:uri])
    http = Net::HTTP.new(uri.host, uri.port)

    if uri.scheme == 'https' then
        http.use_ssl = true
        http.verify_mode = OpenSSL::SSL::VERIFY_NONE
    end

    # Timeout handler, just in case.
    response = nil
    begin
        Timeout::timeout(options[:timeout]) do
            request = Net::HTTP::Get.new(uri.request_uri)
            if (options[:user] and options[:pass]) then
                request.basic_auth(options[:user], options[:pass])
            end
            if (options[:headers]) then
                options[:headers].each do |h|
                    k,v = h.split(':')
                    request[k] = v
                end
            end
            response = http.request(request)
        end
    # Not sure whether a timeout should be CRIT or UNKNOWN. -- phrawzty
    rescue Timeout::Error
        say(options[:v], 'The HTTP connection timed out after %i seconds.' % [options[:timeout]])
        msg = 'CRIT: Connection timed out.'
        do_exit(options[:v], 2, msg)
    rescue Exception => e
        say(options[:v], 'Exception occured: %s.' % [e])
        msg = 'UNKNOWN: HTTP connection failed.'
        do_exit(options[:v], 3, msg)
    end

    # We must get a proper response.
    if not response.code.to_i == 200 then
        msg = 'WARN: Received HTTP code %s instead of 200.' % [response.code]
        do_exit(options[:v], 1, msg)
    end

    say(options[:v], "RESPONSE:\n---\n%s\n---" % [response.body])

    # Make a JSON object from the response.
    json = JSON.parse response.body

    return json
end

# Deal with a file target.
def file_target(options)
    # The file must exist and be readable.
    state = nil

    if not File.exist?(options[:file]) then
        state = 'does not exist'
    elsif not File.readable?(options[:file]) then
        state = 'is not readable'
    end

    if state then
        msg = 'CRIT: %s %s.' % [options[:file], state]
        do_exit(options[:v], 2, msg)
    end

    # Make a JSON object from the contents of the file.
    json = JSON.parse(File.read(options[:file]))

    return json
end

# Parse cli args.
def parse_args(options)
    optparse = OptionParser.new do |opts|
        opts.banner = 'Usage: %s -u <URI> -e <element> -w <warn> -c <crit>' % [$0]

        opts.on('-h', '--help', 'Help info.') do
            puts opts
            do_exit(true, 3, nil)
        end

        options[:v] = false
        opts.on('-v', '--verbose', 'Additional human output.') do
            options[:v] = true
        end

        options[:uri] = nil
        opts.on('-u', '--uri URI', 'Target URI. Incompatible with -f.') do |x|
            options[:uri] = x
        end

        options[:user] = nil
        opts.on('--user USERNAME', 'HTTP basic authentication username.') do |x|
            options[:user] = x
        end

        options[:pass] = nil
        opts.on('--pass PASSWORD', 'HTTP basic authentication password.') do |x|
            options[:pass] = x
        end

        options[:headers] = nil
        opts.on('--headers HEADERS', 'Comma-separated list of HTTP headers to include (ex. HOST:somehost,AUTH:letmein).') do |x|
            options[:headers] = x.split(',')
        end

        options[:file] = nil
        opts.on('-f', '--file PATH', 'Target file. Incompatible with -u.') do |x|
            options[:file] = x
        end

        options[:element_string] = nil
        opts.on('-e', '--element ELEMENT', 'Desired element (ex. foo=>bar=>ish is foo.bar.ish).') do |x|
            options[:element_string] = x
        end

        options[:element_regex] = nil
        opts.on('-E', '--element_regex REGEX', 'Desired element expressed as regular expression.') do |x|
            options[:element_regex] = x
        end

        options[:delimiter] = '.'
        opts.on('-d', '--delimiter CHARACTER', 'Element delimiter (default is period).') do |x|
            options[:delimiter] = x
        end

        options[:warn] = nil
        opts.on('-w', '--warn VALUE', 'Warning threshold (integer).') do |x|
            options[:warn] = x.to_s
        end

        options[:crit] = nil
        opts.on('-c', '--crit VALUE', 'Critical threshold (integer).') do |x|
            options[:crit] = x.to_s
        end

        options[:result_string] = nil
        opts.on('-r', '--result STRING', 'Expected string result. No need for -w or -c.') do |x|
            options[:result_string] = x
        end

        options[:result_regex] = nil
        opts.on('-R', '--result_regex REGEX', 'Expected string result expressed as regular expression. No need for -w or -c.') do |x|
            options[:result_regex] = x
        end

        options[:result_string_warn] = nil
        opts.on('-W', '--result_warn STRING', 'Warning if element is [string]. -C is required.') do |x|
            options[:result_string_warn] = x
        end

        options[:result_string_unknown] = nil
            opts.on('-U', '--result_unknown STRING', 'Unknown if element is [string]. -C is required.') do |x|
            options[:result_string_unknown] = x
        end

        options[:result_string_crit] = nil
        opts.on('-C', '--result_crit STRING', 'Critical if element is [string]. -W is required.') do |x|
            options[:result_string_crit] = x
        end

        options[:perf] = nil
        opts.on('-p', '--perf ELEMENT', 'Output additional fields (performance metrics); comma-separated.') do |x|
            options[:perf] = x.split(',')
        end

        options[:timeout] = 5
        opts.on('-t', '--timeout SECONDS', 'Wait before HTTP timeout.') do |x|
            options[:timeout] = x.to_i
        end
    end

    optparse.parse!
    return options
end

# Sanity check.
def sanity_check(options)
    # In life, some arguments cannot be avoided.
    error_msg = []

    if not (options[:uri] or options[:file]) then
        error_msg.push('Must specify target URI or file.')
    end

    if (options[:user] and not options[:pass]) or (options[:pass] and not options[:user]) then
        error_msg.push('Must specify both a username and a password for basic auth.')
    end

    if (options[:uri] and options[:file]) then
        error_msg.push('Must specify either target URI or file, but not both.')
    end

    if not (options[:element_string] or options[:element_regex]) then
        error_msg.push('Must specify a desired element.')
    end

    if options[:element_string] and options[:element_regex] then
        error_msg.push('Must specify either an element string OR an element regular expression.')
    end

    if options[:delimiter].length > 1
        error_msg.push('Delimiter must be a single character.')
    end

    if not ((options[:result_string] or options[:result_regex]) or (options[:warn] and options[:crit]) or (options[:result_string_warn] and options[:result_string_crit])) then
        error_msg.push('Must specify an expected result OR the warn and crit thresholds.')
    end

    if options[:result_string] and options[:result_regex] then
        error_msg.push('Must specify either a result string OR result regular expression.')
    end

    if error_msg.length > 0 then
        # First line is Nagios-friendly.
        puts 'UNKNOWN: Insufficient or incompatible arguments.'
        # Subsequent lines are for humans.
        error_msg.each do |msg|
            puts msg
        end
        msg = '"%s --help" for more information.' % [$0]
        do_exit(true, 3, msg)
    end
end



# Run Lola Run.

# Choose your arguments wisely.
options = parse_args(options)
sanity_check(options)

# Set up the json object.
json = nil

# If the target is a URI.
if options[:uri] then
    json = uri_target(options)
end

# If the target is a file.
if options[:file] then
    json = file_target(options)
end

# Flatten that bad boy.
json_flat = hash_flatten(json, options[:delimiter])

# If performance metrics have been requested...
perf = ''
if options[:perf].is_a?(Array) then
    p = []
    options[:perf].each do |x|
        if json_flat.has_key?(x) then
            say(options[:v], 'Perf metric %s is %s' % [x, json_flat[x]])
            p.push("%s=%s" % [x, json_flat[x]])
        end
    end
    # Build a nice output string (issue #17).
    perf = ' | ' + p.join(' ')
end

# If the element is a string...
if options[:element_string] then
    if not json_flat.has_key?(options[:element_string]) then
        # Not sure if this should be WARN or CRIT. --phrawzty
        msg = 'WARN: %s not found in response.' % [options[:element_string]] + perf
        do_exit(options[:v], 1, msg)
    end
    options[:element] = options[:element_string]
end

# If the element is a regex...
if options[:element_regex] then
    json_flat.each do |k,v|
        if k =~ Regexp.new(options[:element_regex]) then
            say(options[:v], "Found %s as %s" % [options[:element_regex], k])
            element_found = true
            options[:element] = k
        end
    end
    if not options[:element] then
        msg = 'UNKNOWN: %s not found in response.' % [options[:element_regex]] + perf
        do_exit(options[:v], 3, msg)
    end
end

say(options[:v], 'The value of %s is %s' % [options[:element], json_flat[options[:element]]])

# If we're looking for a string...
if options[:result_string] then
    if json_flat[options[:element]].to_s == options[:result_string].to_s then
        msg = 'OK: %s is %s' % [options[:element], json_flat[options[:element]]] + perf
        do_exit(options[:v], 0, msg)
    else
        msg = 'CRIT: %s is %s' % [options[:element], json_flat[options[:element]]] + perf
        do_exit(options[:v], 2, msg)
    end
end

# If we're looking for a regex...
if options[:result_regex] then
    say(options[:v], 'Will match %s against \'%s\'' % [options[:element].to_s, options[:result_regex]])
    if json_flat[options[:element]].to_s =~ Regexp.new(options[:result_regex]) then
        msg = 'OK: %s is %s' % [options[:element], json_flat[options[:element]]] + perf
        do_exit(options[:v], 0, msg)
    else
        msg = 'CRIT: %s is %s' % [options[:element], json_flat[options[:element]]] + perf
        do_exit(options[:v], 2, msg)
    end
end

# If we're specifying critical & warning strings...
if options[:result_string_warn] and options[:result_string_crit]
    say(options[:v], '%s should not match against \'%s\', else CRIT' % [options[:element].to_s, options[:result_string_crit]])
    say(options[:v], '%s should not match against \'%s\', else WARN' % [options[:element].to_s, options[:result_string_warn]])
    if json_flat[options[:element]].to_s == options[:result_string_crit].to_s then
        msg = 'CRIT: %s matches %s' % [options[:element], json_flat[options[:element]]] + perf
        do_exit(options[:v], 2, msg)
    elsif json_flat[options[:element]].to_s == options[:result_string_warn].to_s then
        msg = 'WARN: %s matches %s' % [options[:element], json_flat[options[:element]]] + perf
        do_exit(options[:v], 1, msg)
    elsif json_flat[options[:element]].to_s == options[:result_string_unknown].to_s then
        msg = 'UNKNOWN: %s matches %s' % [options[:element], json_flat[options[:element]]] + perf
        do_exit(options[:v], 3, msg)
    else 
        msg = 'OK: %s does not match %s or %s' % [options[:element], options[:result_string_warn], options[:result_string_crit]] + perf
        do_exit(options[:v], 0, msg)
    end 
end   

# If we're dealing with threshold values...

# Numbahs only, brah.
if json_flat[options[:element]] =~ /\D/ then
    say(options[:v], 'The value of %s contains non-numeric characters.' % [options[:element]])
    msg = 'UNKNOWN: Return value syntax failure.'
    do_exit(options[:v], 3, msg)
end

if options[:warn] then
    warn = nutty_parse('Warning', options[:warn], json_flat[options[:element]], options[:v], options[:element])
    if warn == 'FAIL'
        msg = 'UNKNOWN: Warn threshold syntax failure.'
        do_exit(options[:v], 3, msg)
    end
end

if options[:crit] then
    crit = nutty_parse('Critical', options[:crit], json_flat[options[:element]], options[:v], options[:element])
    if crit == 'FAIL'
        msg = 'UNKNOWN: Critical threshold syntax failure.'
        do_exit(options[:v], 3, msg)
    end
end

# Assemble the message in order of precedence.
msg = '%s'

if crit != 'OK' then
    msg = 'CRIT: %s' % [crit] + perf
    exit_code = 2
elsif warn != 'OK' then
    msg = 'WARN: %s'% [warn] + perf
    exit_code = 1
else
    msg = 'OK: %s is %s' % [options[:element], json_flat[options[:element]]] + perf
    exit_code = 0
end

# Finally output the message and exit.
do_exit(options[:v], exit_code, msg)
