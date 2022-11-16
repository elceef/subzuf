subzuf
======

*subzuf* is a subdomain brute-force fuzzer coupled with an immensly simple but 
effective DNS reponse-guided algorithm. It utilizes a provided set of input 
data, like a tailored wordlist or historical DNS/TLS records, to accurately 
synthesize more corresponding domain names and expand them even further in a 
loop based on information gathered during DNS scan. This approach in most cases 
allows to discover more subdomains with significantly reduced time and 
resources.

![Demo](/misc/demo.gif)

In short, *subzuf* can be summarized by the following:

- Starting with input data and working in a loop, generates carefully selected 
candidates and uncover completely new subdomains during DNS enumeration scans
- Efficient multi-threaded DNS client capable of resolving thousands of domains 
per second
- Wildcard detection in two modes: filter (default, slightly slower but 
accurate) and reject (resource-saving)
- Accepts wordlist or domain names or a mix of both as input
- Requires essentially no configuration or fine-tuning - at minimum needs only 
target domain name and some quality input data
- Works right of out the box - no external dependencies or bizzare requirements
- Easily chainable with other tools


Usage tips
----------

- The most efficient enumeration happens not with enormous or random input but 
with a mix of targeted test cases generated from OSINT and tailored wordlist.
- Input data is validated and everything that can't be quickly "fixed" on the 
fly will be silently skipped.
- By default the number of threads is auto-selected based on available CPU 
cores, which is a safe and in many cases sufficient value. Although it often 
pays off to increase this number, keep in mind that at some point speed does 
not increase linearly with the number of threads.
- Keep an eye at the error ratio in the status line. It should be reasonably 
low, say less than 1%. The most common errors are socket timeouts due to: 
congested and poor quality network links, slow DNS resolvers, rate-limiting, 
overloaded authoritative nameservers.
- Cloudflare, Google and OpenDNS public DNS resolvers are used by default and 
considered reliable. Feel free to supply your own list of DNS resolvers. 
Although resolvers undergo basic validation test, please ensure that they can 
handle higher loads. Poor quality DNS resolvers will cause excessive timeout 
errors or refused/servfail status responses.
- Colourful CLI output is auto-selected when an interactive terminal is 
detected. Otherwise JSON is used by default. Output format can be always 
enforced with the optional command line argument.


Known limitations and common-sense risks
----------------------------------------

- Active DNS enumeration involves many thousands of queries in a relatively 
short period of time. Keep in mind that such a volume of DNS messages might not 
go unnoticed at the target.
- Virtual machines with NAT network adapters are generally not suitable for 
handling hundreds of DNS packets per second and will likely cause timeout 
errors.
- Built-in DNS client has a bare-minimum implementation required for the task 
and does not support DoH - use a proxy solution if really necessary.


Contact
-------

Questions? Don't hesitate to contact the author. Any feedback is appreciated.
