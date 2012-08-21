check_http_json
===============

This is a plugin for Nagios that will parse JSON from an HTTP response.  It is written in Ruby.

Usage
-----

    Usage: ./check_http_json.rb -u <URI> -e <element> -w <warn> -c <crit>
    -h, --help                       Help info.
    -v, --verbose                    Additional human output.
    -u, --uri URI                    Target URI. Incompatible with -f.
    -f, --file PATH                  Target file. Incompatible with -u.
    -e, --element ELEMENT            Desired element (ex. foo=>bar=>ish is foo.bar.ish).
    -E, --element_regex REGEX        Desired element expressed as regular expression.
    -d, --delimiter CHARACTER        Element delimiter (default is period).
    -w, --warn VALUE                 Warning threshold (integer).
    -c, --crit VALUE                 Critical threshold (integer).
    -r, --result STRING              Expected string result. No need for -w or -c.
    -R, --result_regex REGEX         Expected string result expressed as regular expression. No need for -w or -c.
    -W, --result_warn STRING         Warning if element is [string]. -C is required.
    -C, --result_crit STRING         Critical if element is [string]. -W is required.
    -t, --timeout SECONDS            Wait before HTTP timeout.

The `--warn` and `--crit` arguments conform to the Nagios [threshold format guidelines].

If a simple result of either string or regular expression (`-r` or `-R`) is specified :

* A match is OK and anything else is CRIT.
* The warn / crit thresholds will be ignored.

If the warn and crit results (`-W` and `-C`) are specified :

* A match is WARN or CRIT and anything else is OK.
* The warn / crit thresholds will be ignored.

Note that (`-r` or `-R`) and (`-W` and `-C`) are mutually exclusive.

Note also that the response must be pure JSON.  Bad things happen if this isn't the case.

Implementation
--------------

How you choose to implement the plugin is, of course, up to you.  Here are some suggestions :

### given string element, check string result
    define command {
        command_name    check_http_json-string
        command_line    /etc/nagios3/plugins/check_http_json.rb -u 'http://$HOSTNAME$:$ARG1$/$ARG2$' -e '$ARG3$' -r '$ARG4$'
    }
    define service {
        service_description     elasticsearch-cluster-status
        check_command           check_http_json-string!9200!_cluster/health!status!green
    }

### wildly generic
    define command {
        command_name    check_http_json
        command_line    /etc/nagios3/plugins/check_http_json.rb -u 'http://$HOSTNAME$:$ARG1$/$ARG2$' $ARG3$
    }
    define service {
        service_description     elasticsearch-resident-memory
        check_command           check_http_json!9280!_cluster/nodes/_local/stats!-E resident_in_bytes -w 1024000000 -c 1536000000
    }

The script is licensed using the [Apache License], Version 2.0.

Finally, I invite you to peruse the [commit history] for the list of contributors.

GitHub pull requests welcome !  Please send pull requests to the **testing** branch.

[threshold format guidelines]: http://nagiosplug.sourceforge.net/developer-guidelines.html
[Apache License]: http://www.apache.org/licenses/LICENSE-2.0
[commit history]: https://github.com/phrawzty/check_http_json/commits
