import re

import pytest

from reconic.scope import Scope, host_of


def test_host_of_handles_hosts_urls_and_garbage():
    assert host_of('API.Example.com.') == 'api.example.com'
    assert host_of('https://app.example.com:8443/a?b=1') == 'app.example.com'
    assert host_of('app.example.com:8080/path') == 'app.example.com'
    assert host_of('http://10.0.0.5/') == '10.0.0.5'
    assert host_of('') is None
    assert host_of('not a host') is None
    assert host_of('javascript:alert(1)') is None


def test_exact_host_does_not_widen_to_siblings():
    scope = Scope(['app.example.com'])
    assert scope.allows('https://app.example.com/login')
    assert not scope.allows('example.com')
    assert not scope.allows('api.example.com')
    assert scope.enumeration_roots() == []
    assert scope.exact_hosts() == ['app.example.com']


def test_wildcard_matches_any_depth_but_not_apex_or_lookalikes():
    scope = Scope(['*.example.com'])
    assert scope.allows('a.example.com')
    assert scope.allows('a.b.c.example.com')
    assert not scope.allows('example.com')
    assert not scope.allows('evilexample.com')
    assert not scope.allows('example.com.evil.net')
    assert not scope.allows('a.example.com.evil.net')
    assert scope.enumeration_roots() == ['example.com']


def test_exclusions_win():
    scope = Scope(['example.com', '*.example.com'], ['admin.example.com', '*.corp.example.com'])
    assert scope.allows('www.example.com')
    assert not scope.allows('admin.example.com')
    assert not scope.allows('https://vpn.corp.example.com/')
    assert scope.exact_hosts() == ['example.com']


def test_patterns_are_normalised_and_validated():
    scope = Scope(['https://App.Example.com:8443/path', 'api-*.example.com'])
    assert scope.include == ['app.example.com', 'api-*.example.com']
    assert scope.allows('api-v2.example.com')
    assert not scope.allows('api.example.com')
    with pytest.raises(ValueError):
        Scope(['exa mple.com'])
    with pytest.raises(ValueError):
        Scope([])


def test_networks():
    scope = Scope(['10.0.0.0/24'], ['10.0.0.9'])
    assert scope.allows('http://10.0.0.5:8080/')
    assert not scope.allows('10.0.1.5')
    assert not scope.allows('10.0.0.9')
    assert not scope.allows('example.com')
    assert scope.url_regexes() is None


def test_split_dedupes_and_counts_dropped():
    scope = Scope(['*.example.com'])
    kept, dropped = scope.split(['a.example.com', 'a.example.com', 'x.other.net', '', 'b.example.com'])
    assert kept == ['a.example.com', 'b.example.com']
    assert dropped == 1


def test_scope_file(tmp_path):
    path = tmp_path / 'scope.txt'
    path.write_text("# program scope\n*.example.com\nexample.com  # apex\n\n!admin.example.com\n")
    include, exclude = Scope.parse_file(path)
    assert include == ['*.example.com', 'example.com']
    assert exclude == ['admin.example.com']


def test_url_regexes_agree_with_allows():
    scope = Scope(['example.com', '*.example.com'], ['admin.example.com'])
    included, excluded = scope.url_regexes()

    def crawler_allows(url):
        return (any(re.search(r, url) for r in included)
                and not any(re.search(r, url) for r in excluded))

    for url in ['https://example.com', 'http://a.b.example.com:8080/x?y=1', 'https://admin.example.com/',
                'https://evilexample.com/', 'https://example.com.evil.net/', 'https://other.net/?u=example.com']:
        assert crawler_allows(url) == scope.allows(url), url
    assert not any(',' in r for r in included + excluded)  # tool flags split values on commas


def test_networks_are_expanded_into_seed_hosts():
    scope = Scope(['app.example.com', '10.0.0.0/29', '10.0.0.6'], ['10.0.0.4/31'])
    assert scope.seeds() == ['app.example.com', '10.0.0.6', '10.0.0.1', '10.0.0.2', '10.0.0.3']
    assert Scope(['10.0.0.5/32']).seeds() == ['10.0.0.5']
    assert scope.exact_hosts() == ['app.example.com', '10.0.0.6']
    with pytest.raises(ValueError, match='65536'):
        Scope(['10.0.0.0/8'])
    Scope(['app.example.com'], ['10.0.0.0/8'])  # an excluded network can be any size


def test_wildcards_are_enumerated_from_their_fixed_suffix():
    assert Scope(['api-*.example.com']).enumeration_roots() == ['example.com']
    assert Scope(['*.dev.*.example.co.uk', '*.example.co.uk']).enumeration_roots() == ['example.co.uk']
    for pattern in ('example.*', '*.com', 'www.*.com'):
        scope = Scope([pattern])
        assert scope.enumeration_roots() == [] and scope.unseeded() == [pattern]
    assert Scope(['*.example.com', '10.0.0.0/30', 'a.example.com']).unseeded() == []
