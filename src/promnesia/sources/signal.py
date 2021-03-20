"""
Harvest visits from Signal Desktop's chiphered SQLIite db(s).

Functions get their defaults from module-data.

* Adapted from https://github.com/carderne/signal-export/commit/2284c8f4
* Copyright (c) 2019 Chris Arderne, 2020 Kostis Anagnostopoulos
"""

import contextlib
from dataclasses import dataclass, field
import io
import json
import logging
import platform
import sqlite3
import subprocess as sbp
from pathlib import Path
from textwrap import dedent, indent
from typing import Any, Iterable, Mapping, Sequence, Tuple, Union

from ..common import Loc, PathIsh, Results, Visit, extract_urls, from_epoch

PathIshes = Union[PathIsh, Iterable[PathIsh]]

#: A mapping of ``platform.system()`` values --> (possibly globbing) paths.
platform_db_paths: Mapping[str, PathIsh] = {
    "Linux": "~/.config/Signal/sql/db.sqlite",
    "Darwin": "~/Library/Application Support/Signal/sql/db.sqlite",
    "Windows": "~/AppData/Roaming/Signal/sql/db.sqlite",
}
#: SQL PRAGMAs sent before opening the database (after ``PRAGMA key = x'...';``)
decryption_pragmas = {
    ## Not required, but good to be explicit.
    "cipher_compatibility": 4,
    ## Really old installation?
    # "cipher_compatibility": 3,
    ## Pragmas for cipher_compatibility-4:
    # "cipher_page_size": "4096",
    # "cipher_hmac_algorithm": "HMAC_SHA512",
    # "cipher_kdf_algorithm": "PBKDF2_HMAC_SHA512",
    ## Pragmas for cipher_compatibility-3
    # "cipher_page_size": "1024",
    # "cipher_hmac_algorithm": "HMAC_SHA1",
    # "cipher_kdf_algorithm": "PBKDF2_HMAC_SHA1",
}

messages_query = dedent(
    """
    WITH
    Cons AS (
        SELECT
            id,
            type,
            coalesce(name, profileName, profileFamilyName, e164) as aname,
            name,
            profileName,
            profileFamilyName,
            e164,
            uuid
        FROM conversations
    ),
    Msgs AS (
        SELECT
            M.id,
            M.type as mtype,
            M.isErased,
            coalesce(
                M.received_at,
                M.sent_at
            ) AS timestamp,
            IIF(M.type = "outgoing",
                "Me (" || C2.aname || ")",
                C2.aname
            ) AS sender,
            M.conversationId AS cid,
            C1.aname AS chatname,
            C1.name,
            C1.profileName,
            C1.profileFamilyName,
            C1.type as ctype,
            M.body
        FROM messages as M
        INNER JOIN Cons AS C1
            ON M.conversationId = C1.id
        INNER JOIN Cons AS C2
            ON M.sourceUuid = C2.uuid
    )
    SELECT id, timestamp, sender, cid, chatname, body
    FROM Msgs
    WHERE body LIKE '%http%'
    """
)


logger = logging.getLogger(__name__)


# TODO: move CliError to `..commons` package
class CliError(Exception):
    """
    Report a polite error message and exit application with given code.

    >>> raise CliError(1, "Hi!")
    Traceback (most recent call last):
    promnesia.sources.signal.CliError: (1) Hi!
    """

    def __init__(self, code: int, msg: str) -> None:
        super().__init__(code, msg)

    @property
    def code(self) -> int:
        return self.args[0]

    @property
    def msg(self) -> str:
        return self.args[1]

    def __str__(self) -> str:
        return f"({self.code}) {self.msg}"


def _is_pathish(p) -> bool:
    """returns true if str or pathlin.Path."""
    return isinstance(p, (str, Path))


def _expand_path(path: PathIsh) -> Iterable[Path]:
    """
    Expand homedir(`~`) and return any (optionally) globed paths matching.

    Expansion code copied from https://stackoverflow.com/a/51108375/548792
    """
    if not path:
        return ()
    path = Path(path).expanduser()
    parts = path.parts[1:] if path.is_absolute() else path.parts
    return Path(path.root).glob(str(Path("").joinpath(*parts)))


def _expand_paths(paths: PathIshes) -> Iterable[Path]:
    if _is_pathish(paths):
        paths = [paths]
    return [pp.resolve() for p in paths for pp in _expand_path(p)]


def collect_db_paths(*db_paths: PathIsh, append=None) -> PathIshes:
    """
    Get OS-dependent (or user overridden) db locations (1st existing used).

    :param db_paths:
        optional path(s) to search for db file in-order, overriding OS-platform's defaults.
    :param append:
        if true, use given `db_paths` in addition to :data:`platform_db_paths`
    :return:
        one or more pathish

    Note: needed `append` here, to resolve paths.
    
    >>> bool(collect_db_paths())  # my home-path
    True
    >>> collect_db_paths(None)
    []
    >>> collect_db_paths([])
    []
    >>> collect_db_paths('NOT_EXISTS')
    []
    >>> collect_db_paths("~/..")  # posix-only
    [PosixPath('/home')]
    >>> collect_db_paths('NOT_EXISTS', '/usr/*')
    [PosixPath('/usr/lib'),
     PosixPath('/usr/local'),
     PosixPath('/usr/share'),
    ...
    >>> len(collect_db_paths('/usr', append=True)) - len(collect_db_paths('/usr'))
    1
    """
    if append or not db_paths:
        platform_name = platform.system()
        try:
            plat_paths = platform_db_paths[platform_name]
        except LookupError:
            raise ValueError(
                f"Unknown platform({platform_name}!"
                f"\n  Expected one of {list(platform_db_paths.keys)}."
            )

        if db_paths and append:
            db_paths = [
                *([db_paths] if _is_pathish(db_paths) else db_paths),
                plat_paths,
            ]
        else:
            db_paths = plat_paths

    return _expand_paths(db_paths)


def _config_for_dbfile(db_path: Path, default_key=None) -> Path:
    """Return `default_key` if :file:`{db_path}/../../config.json`` does not exist."""
    cfg_path = db_path.parents[2] / "config.json"
    return cfg_path


def _key_from_config(signal_desktop_config_path: PathIsh) -> str:
    with open(signal_desktop_config_path, "r") as conf:
        return json.load(conf)["key"]


@contextlib.contextmanager
def connect_db(
    db_path: Path,
    key,
    decrypt_db: bool = None,
    sqlcipher_exe: PathIsh = "sqlcipher",
    **decryption_pragmas: Mapping[str, Any],
) -> sqlite3.Connection:
    """
    Opens (or decrypt) a ciphered sqlite db in a context.

    :param key:
        as extracted from :file:`config.json',
        see https://www.zetetic.net/sqlcipher/sqlcipher-api/#PRAGMA_key
    :param decrypt_db:
        if true, fully decrypt db into a temporary db-file using `sqlcipher` standalone program;
        the program must be in the PATH, or its path given in `sqlcipher_exe`.
        The temporary db-file is deleted when the context is exited.

        NOTE: The ``pysqlcipher3`` python library is not imported.
    :param sqlcipher_exe:
        the path to the `sqlcipher` standalone program;  only used if `decrypt_db` is true.
    :param decryption_pragmas:
        used to unlock older dbs;  see :data:`decryption_pragmas`.

    :return:
        the db-connection, which is closed when the context is exited
    :raises pysqlcipher3.dbapi2.DatabaseError:
        when key was invalid and `decrypt_db` was false
    :raises sbp.SubprocessError:
        when key is invalid and `decrypt_db` was true,
        with text _"file is not a database"_
    """
    logger.info(
        "Opening encrypted-db%s: %s",
        db_path,
        f" with {sqlcipher_exe}" if decrypt_db else "",
    )
    db = decrypted_file = None
    sql_cmds = [
        f"PRAGMA key = \"x'{key}'\";",
        *(f"PRAGMA {k} = {v};" for k, v in decryption_pragmas.items()),
    ]

    try:
        if decrypt_db:
            decrypted_file = db_path.parent / "db-decrypted.sqlite"
            if decrypted_file.exists():
                decrypted_file.unlink()
            sql_cmds.extend(
                [
                    f"ATTACH DATABASE '{decrypted_file}' AS plaintext KEY '';",
                    f"SELECT sqlcipher_export('plaintext');",
                    f"DETACH DATABASE plaintext;",
                ]
            )
            sql = "\n".join(sql_cmds)
            cmd = [sqlcipher_exe, str(db_path)]
            logger.debug(
                "Decrypting db '%s' with cmd: %s <<<EOF\n%s\nEOF", db_path, cmd, sql
            )
            try:
                sbp.run(
                    cmd,
                    check=True,
                    input=sql,
                    capture_output=True,
                    universal_newlines=True,
                )
            except sbp.CalledProcessError as ex:
                prefix = " " * 4
                raise sbp.SubprocessError(
                    f"{sqlcipher_exe}: failed with code({ex.returncode}) to decrypt db: {db_path}"
                    f"\n   +--SQL:\n{indent(sql, prefix)}\n  +--STDERR:\n{indent(ex.stderr, prefix)}",
                ) from None
            db = sqlite3.connect(f"file:{decrypted_file}?mode=ro", uri=True)
        else:
            from pysqlcipher3 import dbapi2

            db = dbapi2.connect(f"file:{db_path}?mode=ro", uri=True)
            # Param-binding doesn't work for pragmas, so use a direct string concat.
            sql = "\n".join(sql_cmds)
            db.executescript(sql)

            ## Check db indeed unlocked.
            #  Check is necessary only here;  The `sqlcipher` method, above, fails early.
            list(db.execute("SELECT count(*) FROM sqlite_master;"))

        yield db
    finally:
        try:
            if db:
                db.close()
        finally:
            if decrypted_file and decrypted_file.exists():
                try:

                    logger.debug("Deleting temporary decrypted db: %s", decrypted_file)
                    decrypted_file.unlink()
                except Exception as ex:
                    logger.warning(
                        "Ignored error while deleting temporary decrypted db file(%s): %s",
                        decrypted_file,
                        ex,
                        exc_info=logger.isEnabledFor(logging.DEBUG),
                    )


def _handle_row(row: dict, db_path: PathIsh, locator_schema: str) -> Results:
    mid, tstamp, sender, cid, chatname, text = row
    urls = extract_urls(text)
    if not urls:
        return

    assert (
        text and mid and sender and chatname
    ), f"sql-query should eliminate messages without 'http' or missing ids: {row}"

    if tags and tags.strip():
        tags = "".join(f"#{t}" for t in tags.split())
        text = f"{text}\n\n{tags}"

    url_title = _parse_json_title(infojson)
    if url_title:
        text = f"title: {url_title}\n\n{text}"

    for u in urls:
        yield Visit(
            url=u,  # URLs in Viber's SQLite are not quoted
            dt=dt,
            context=text,
            locator=Loc.make(
                title=f"chat({mid}) from {sender}@{chatname}",
                href=f"{locator_schema}://{db_path}#!Messages.EventId={mid}",
            ),
        )


def _harvest_db(
    db_path: Path,
    override_key: str=None,
    msgs_query: str=None,
    locator_schema: str="editor",
    decrypt_db: bool = None,
    **decryption_pragmas,
) -> Iterable[Visit]:
    """
    Harvest db  `db_path` and yield visits.

    See :func:`connect_db()` for `db_path`, `key` params.

    :param override_key:
        when not given, extracted from ``../config.json`` relative to `db_path`
    :param msgs_query:
        read code for which columns it must fetch, uses :data:`messages_query` if not given
    :param locator_schema:
        see :func:`index()`
    """
    is_debug = logger.isEnabledFor(logging.DEBUG)

    if override_key:
        key = override_key
    else:
        cfg_path = _config_for_dbfile(db_path)
        key = _key_from_config(cfg_path)

    with connect_db(db_path, key, decrypt_db=decrypt_db, **decryption_pragmas) as db:
        for mid, tstamp, sender, cid, chatname, text in db.execute(msgs_query):
            try:
                tstamp = from_epoch(tstamp / 1000.0)
                row = (mid, tstamp, sender, cid, chatname, text)
                yield from _handle_row(row, db_path, locator_schema)
            except Exception as ex:
                # TODO: also insert errors in db
                logger.warning(
                    "Cannot extract row: %s, due to: %s(%s)",
                    row,
                    type(ex).__name__,
                    ex,
                    exc_info=is_debug,
                )

@dataclass
class SignalConfig:
    """
    :param db_paths:
        one or many ciphered sqlite paths to harvest;
        if non/empty, use default path for platform,
        as prvided by :func:`db_paths()`.
    :param append_platform_path:

    :param locator_schema:
        the uri-schema for generated visits
    :param decrypt_db:
        see :func:`connect_db()`
    :param decryption_pragmas:
        see :func:`connect_db()`

    """
    db_paths: PathIshes = None,
    append_platform_path: bool = None,
    decrypt_db: bool = None,
    override_key: str=None,
    decryption_pragmas: Mapping[str, Any]=None,
    msgs_query: str=None,
    locator_schema="editor",

def index(*args, **kw) -> Results:
    """See :class:`SignalConfig` for arguments. """
    logger.debug(
        "Append platform path?(%s) on top user paths: %s",
        db_paths,
        append_platform_path,
    )
    db_paths = collect_db_paths(db_paths, append_platform_path)
    logger.debug("Paths to harvest: %s", db_paths)

    for db_path in db_paths:
        logger.info("Ciphered db to harvest %s", db_path)
        assert db_path.is_file(), f"Is it a (Signal-desktop sqlite) file? {db_path}"
        yield from _harvest_db(db_path, override_key, messages_query, locator_schema)
