# `check_http_json.rb`

This is a plugin for Nagios that will parse JSON from an HTTP response. It is written in Ruby and is known to function in versions 1.8.7, 1.9.3, and 2.4.0.

## Usage

```
Usage: /usr/local/nagios/plugins/alphatrek/check_http_json.rb -u <URI> -e <element> -w <warn> -c <crit>
    -h, --help                       Help info.
    -v, --verbose                    Additional human output.
    -u, --uri URI                    Target URI. Incompatible with -f.
        --user USERNAME              HTTP basic authentication username.
        --pass PASSWORD              HTTP basic authentication password.
        --headers HEADERS            Comma-separated list of HTTP headers to include (ex. HOST:somehost,AUTH:letmein).
        --status_level STRING        Comma-separated list of HTTP status codes and their associated Nagios alert levels (ex. 301:1,404:2).
    -f, --file PATH                  Target file. Incompatible with -u.
    -e, --element ELEMENT...         Desired element (ex. foo=>bar=>ish is foo.bar.ish). Repeatable argument.
    -E, --element_regex REGEX        Desired element expressed as regular expression.
        --element_regex_global       Check all occurring matches. -E is required.
    -d, --delimiter CHARACTER        Element delimiter (default is period).
    -w, --warn VALUE                 Warning threshold (integer).
    -c, --crit VALUE                 Critical threshold (integer).
    -r, --result STRING              Expected string result. No need for -w or -c.
    -R, --result_regex REGEX         Expected string result expressed as regular expression. No need for -w or -c.
    -W, --result_warn STRING         Warning if element is [string]. -C is required.
    -U, --result_unknown STRING      Unknown if element is [string]. -C is required.
    -C, --result_crit STRING         Critical if element is [string]. -W is required.
    -X, --result_warn_regex REGEX    Warning if element matches REGEX. -C is required.
    -V, --result_unknown_regex REGEX Unknown if element matches REGEX. -C is required.
    -D, --result_crit_regex REGEX    Critical if element matches REGEX. -W is required.
    -p, --perf ELEMENT               Output additional fields (performance metrics); comma-separated.
    -t, --timeout SECONDS            Wait before HTTP timeout.
```

The `--warn` and `--crit` arguments conform to the Nagios [threshold format guidelines].

If a simple result of either string or regular expression (`-r` or `-R`) is specified:

* A match is OK and anything else is CRIT.
* The warn / crit thresholds will be ignored.

If the warn and crit results (`-W` and `-C`) or regular expressions (`-X` and `-D`) are specified:

* A match is WARN or CRIT and anything else is OK.
* The warn / crit thresholds will be ignored.

Note that (`-r` or `-R`), (`-W` and `-C`), and  (`-X` and `-D`) are mutually exclusive.

Note also that the response must be pure JSON. Bad things happen if this isn't the case.

## Implementation

How you choose to implement the plugin is up to you. Here are some suggestions:

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

### How are you implementing it ?

I encourage you to add your implementation to the [wiki] - that way everybody can benefit!
 
## Fin

The script is licensed using the [Apache License], Version 2.0.

Finally, I invite you to peruse the list of [contributors]; thank you, all!

GitHub pull requests welcome.

[threshold format guidelines]: http://nagiosplug.sourceforge.net/developer-guidelines.html
[Apache License]: http://www.apache.org/licenses/LICENSE-2.0
[wiki]: https://github.com/phrawzty/check_http_json/wiki
[contributors]: https://github.com/phrawzty/check_http_json/graphs/contributors
