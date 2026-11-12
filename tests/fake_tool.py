"""Stand-in for subfinder/dnsx/httpx/katana/nuclei so tests never touch the network.

Behaviour follows the name it is invoked as. Environment switches:
  FAKE_LOG       file that receives one JSON line per invocation (name + args)
  FAKE_FAIL      comma-separated tool names that exit 3 with a message on stderr
  FAKE_FAIL_STDOUT  like FAKE_FAIL, but exits 2 with the message on stdout
  FAKE_HANG      comma-separated tool names that print one line, then sleep
  FAKE_IMPOSTOR  comma-separated binary names that are "some other program"
  FAKE_LABELS    comma-separated subdomain labels subfinder reports (default www,api,admin)
  FAKE_FETCH     comma-separated http:// URLs katana requests through the proxy it was given
"""
import json
import os
import sys
import time

name = os.path.basename(sys.argv[0])
args = sys.argv[1:]


def switched(variable):
    return name in os.environ.get(variable, '').split(',')


def value(flag):
    return args[args.index(flag) + 1]


def read(flag):
    with open(value(flag), encoding='utf-8') as handle:
        return [line.strip() for line in handle if line.strip()]


if '-version' in args:
    if switched('FAKE_IMPOSTOR'):
        print("Error: No such option: -e", file=sys.stderr)
        sys.exit(2)
    if name == 'nuclei':  # nuclei words its banner differently from the other tools
        print("[\033[34mINF\033[0m] Nuclei Engine Version: v3.9.0", file=sys.stderr)
    else:
        print("[\033[34mINF\033[0m] Current Version: v1.2.3", file=sys.stderr)
    sys.exit(0)

if os.environ.get('FAKE_LOG'):
    with open(os.environ['FAKE_LOG'], 'a', encoding='utf-8') as log:
        log.write(json.dumps({'tool': name, 'args': args}) + '\n')

if switched('FAKE_FAIL_STDOUT'):
    print("invalid value for flag -x")
    sys.exit(2)

if switched('FAKE_FAIL'):
    print("boom: simulated failure", file=sys.stderr)
    sys.exit(3)

if switched('FAKE_HANG'):
    print("partial.example.com", flush=True)
    time.sleep(120)

if name == 'subfinder':
    for domain in read('-dL'):
        for label in os.environ.get('FAKE_LABELS', 'www,api,admin').split(','):
            print(f"{label}.{domain}")
    print("cdn.other-company.net")
elif name == 'dnsx':
    for host in read('-l'):
        if not host.startswith('dead'):  # names starting with 'dead' have no DNS record
            print(json.dumps({'host': host, 'a': ['192.0.2.10'], 'status_code': 'NOERROR'}))
elif name in ('httpx', 'httpx-toolkit'):
    for host in read('-l'):
        print(json.dumps({'url': f"https://{host}", 'input': host, 'status_code': 200,
                          'title': f"Home of {host}", 'tech': ['nginx']}))
elif name == 'katana':
    if os.environ.get('FAKE_FETCH'):
        import urllib.request
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({'http': value('-proxy')}))
        for url in os.environ['FAKE_FETCH'].split(','):
            try:
                opener.open(url, timeout=10).read()
            except OSError:
                pass
    for url in read('-list'):
        print(f"{url}/login")
        print(f"{url}/api/v1/users?id=1")
    print("https://tracker.other-company.net/pixel.gif")
elif name == 'nuclei':
    targets = read('-l')
    first = targets[0]
    if '-tags' in args:
        print(json.dumps({'template-id': 'github-takeover', 'type': 'http', 'host': first, 'matched-at': first,
                          'info': {'name': 'GitHub Pages takeover', 'severity': 'high'}}))
    else:
        print(json.dumps({'template-id': 'exposed-git-config', 'type': 'http', 'host': first,
                          'matched-at': f"{first}/.git/config",
                          'info': {'name': 'Git config exposed', 'severity': 'medium'}}))
        print(json.dumps({'template-id': 'offsite-redirect', 'type': 'http', 'host': first,
                          'matched-at': 'https://other-company.net/landing',
                          'info': {'name': 'Offsite', 'severity': 'high'}}))
        print("this line is not json")
