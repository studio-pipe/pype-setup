import os

try:
    from urllib.parse import urlparse, parse_qs, unquote, urlsplit, urlunsplit
except ImportError:
    from urlparse import urlparse, parse_qs


class MongoEnvNotSet(Exception):
    pass


def build_netloc(host, port):
    # type: (str, Optional[int]) -> str
    """
    Build a netloc from a host-port pair
    """
    if port is None:
        return host
    if ':' in host:
        # Only wrap host with square brackets when it is IPv6
        host = '[{}]'.format(host)
    return '{}:{}'.format(host, port)


def build_url_from_netloc(netloc, scheme='https'):
    # type: (str, str) -> str
    """
    Build a full URL from a netloc.
    """
    if netloc.count(':') >= 2 and '@' not in netloc and '[' not in netloc:
        # It must be a bare IPv6 address, so wrap it with brackets.
        netloc = '[{}]'.format(netloc)
    return '{}://{}'.format(scheme, netloc)


def parse_netloc(netloc):
    # type: (str) -> Tuple[str, Optional[int]]
    """
    Return the host-port pair from a netloc.
    """
    url = build_url_from_netloc(netloc)
    parsed = urlparse(url)
    return parsed.hostname, parsed.port


def split_auth_from_netloc(netloc):
    """
    Parse out and remove the auth information from a netloc.

    Returns: (netloc, (username, password)).
    """
    if '@' not in netloc:
        return netloc, (None, None)

    # Split from the right because that's how urllib.parse.urlsplit()
    # behaves if more than one @ is present (which can be checked using
    # the password attribute of urlsplit()'s return value).
    auth, netloc = netloc.rsplit('@', 1)
    if ':' in auth:
        # Split from the left because that's how urllib.parse.urlsplit()
        # behaves if more than one : is present (which again can be checked
        # using the password attribute of the return value)
        user_pass = auth.split(':', 1)
    else:
        user_pass = auth, None

    user_pass = tuple(
        None if x is None else unquote(x) for x in user_pass
    )

    return netloc, user_pass


def _transform_url(url, transform_netloc):
    """Transform and replace netloc in a url.

    transform_netloc is a function taking the netloc and returning a
    tuple. The first element of this tuple is the new netloc. The
    entire tuple is returned.

    Returns a tuple containing the transformed url as item 0 and the
    original tuple returned by transform_netloc as item 1.
    """
    purl = urlsplit(url)
    netloc_tuple = transform_netloc(purl.netloc)
    # stripped url
    url_pieces = (
        purl.scheme, netloc_tuple[0], purl.path, purl.query, purl.fragment
    )
    surl = urlunsplit(url_pieces)
    return surl, netloc_tuple


def _get_netloc(netloc):
    return split_auth_from_netloc(netloc)


def _redact_netloc(netloc):
    return (redact_netloc(netloc),)


def split_auth_netloc_from_url(url):
    # type: (str) -> Tuple[str, str, Tuple[str, str]]
    """
    Parse a url into separate netloc, auth, and url with no auth.

    Returns: (url_without_auth, netloc, (username, password))
    """
    url_without_auth, (netloc, auth) = _transform_url(url, _get_netloc)
    return url_without_auth, netloc, auth


def remove_auth_from_url(url):
    # type: (str) -> str
    """Return a copy of url with 'username:password@' removed."""
    # username/pass params are passed to subversion through flags
    # and are not recognized in the url.
    return _transform_url(url, _get_netloc)[0]


def redact_auth_from_url(url):
    # type: (str) -> str
    """Replace the password in a given url with ****."""
    return _transform_url(url, _redact_netloc)[0]


def decompose_url(url):
    components = {
        "scheme": None,
        "host": None,
        "port": None,
        "path": None,
        "username": None,
        "password": None,
        "auth_db": None,
        "ssl": None,
    }

    result = urlparse(url)
    if result.scheme is None:
        _url = "mongodb://{}".format(url)
        result = urlparse(_url)
    if result.netloc is not None:
        components["scheme"]=result.scheme or "mongodb"
        url_without_auth, netloc, (components["username"], components["password"])=split_auth_netloc_from_url(url)
        components["host"], components["port"] = parse_netloc(netloc)
        components["path"]=result.path
        
        components["auth_db"]=parse_qs(result.query)['authSource'][0]
        components["ssl"]=parse_qs(result.query)['ssl'][0]
    else:
        components["scheme"] = result.scheme
        components["host"] = result.hostname
        try:
            components["port"] = result.port
        except ValueError:
            raise RuntimeError("invalid port specified")
        components["username"] = result.username
        components["password"] = result.password

        try:
            components["auth_db"] = parse_qs(result.query)['authSource'][0]
        except KeyError:
            # no auth db provided, mongo will use the one we are connecting to
            pass
        components["ssl"]=None
    return components


def compose_url(scheme=None,
                host=None,
                username=None,
                password=None,
                port=None,
                path=None,
                auth_db=None,
                ssl=None):

    url = "{scheme}://"

    if username and password:
        url += "{username}:{password}@"

    url += "{host}"
    if port:
        url += ":{port}"
    if path:
        url += "{path}"
    if auth_db and ssl:
        url += "?authSource={auth_db}&ssl=true"
    elif auth_db:
        url += "?authSource={auth_db}"
    else:
        url += "?ssl=true"

    url_str=url.format(**{
        "scheme": scheme,
        "host": host,
        "username": username,
        "password": password,
        "path": path,
        "port": port,
        "auth_db": auth_db
    })
    return url_str


def get_default_components():
    mongo_url = os.environ.get("AVALON_MONGO")
    if mongo_url is None:
        raise MongoEnvNotSet(
            "URL for Mongo logging connection is not set."
        )
    return decompose_url(mongo_url)
