from __future__ import annotations

import asyncio
import base64
import importlib.util
import pkgutil
import pprint
import sys
import threading
from collections.abc import Iterator, Sequence
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass
from datetime import datetime, timedelta
from functools import lru_cache, partial
from importlib.abc import Loader, MetaPathFinder
from importlib.machinery import ModuleSpec
from logging import getLogger
from types import ModuleType
from typing import Annotated, Any, NewType, Self

from pydantic import AnyUrl, BaseModel, BeforeValidator, ConfigDict, Field
from pygamlastan import xml as pg_xml
from pygamlastan.compat import saml2 as saml2_compat
from pygamlastan.compat.saml2 import BINDING_HTTP_POST, BINDING_HTTP_REDIRECT, SAMLError
from pygamlastan.compat.saml2.client import Saml2Client
from pygamlastan.compat.saml2.config import SPConfig
from pygamlastan.compat.saml2.mdstore import SourceNotFound
from pygamlastan.compat.saml2.response import AuthnResponse, SignatureError, StatusError, UnsolicitedResponse
from pygamlastan.compat.saml2.saml import Subject
from pygamlastan.compat.saml2.sigver import MissingKey
from pygamlastan.compat.saml2.typing import SAMLHttpArgs
from pymongo import MongoClient, WriteConcern
from pymongo.errors import DuplicateKeyError, PyMongoError

from auth_server.config import AuthServerConfig, load_config
from auth_server.db.client import create_sync_mongo_client
from auth_server.db.mongo_cache import MongoCache
from auth_server.saml2_mdq import LazyMetadataStore, LazySPConfig, MDQMetadataSource, reload_metadata_source
from auth_server.time_utils import utc_now

__author__ = "lundberg"

logger = getLogger(__name__)

AuthnRequestRef = NewType("AuthnRequestRef", str)


class BadSAMLResponse(Exception):
    """A SAML response that is refused. The message is a constant, safe to show to the client."""


class SAMLServerError(Exception):
    """An unexpected fault (config or programming error) while processing a SAML response, answered with HTTP 500"""


@dataclass
class SAML2SP:
    client: Saml2Client
    outstanding_queries_cache: OutstandingQueriesCache
    authn_req_cache: AuthenticationRequestCache
    single_idp: str | None = None
    discovery_service_url: AnyUrl | None = None
    authn_sign_alg: str = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
    authn_digest_alg: str = "http://www.w3.org/2001/04/xmlenc#sha256"
    authentication_context_map: dict[str, str] = Field(default_factory=dict)


class AuthnInfo(BaseModel):
    authn_class: str
    authn_authority: list[str] = Field(default_factory=list)
    authn_instant: datetime


class NameID(BaseModel):
    format: str
    name_qualifier: str | None = None
    sp_name_qualifier: str | None = None
    sp_provided_id: str | None = None
    id: str


# pysaml returns attributes in lists, lets unwind all string attributes
def unwind_pysaml_str(v: list | str) -> str:
    if isinstance(v, list):
        return v[0]
    return v


PySAMLStr = Annotated[str, BeforeValidator(unwind_pysaml_str)]


class SAMLAttributes(BaseModel):
    assurance: list[str] = Field(default_factory=list, alias="eduPersonAssurance")
    common_name: PySAMLStr | None = Field(default=None, alias="cn")
    country_code: PySAMLStr | None = Field(default=None, alias="c")
    country_name: PySAMLStr | None = Field(default=None, alias="co")
    date_of_birth: PySAMLStr | None = Field(default=None, alias="schacDateOfBirth")
    display_name: PySAMLStr | None = Field(default=None, alias="displayName")
    entitlement: list[str] = Field(default_factory=list, alias="eduPersonEntitlement")
    eppn: PySAMLStr | None = Field(default=None, alias="eduPersonPrincipalName")
    given_name: PySAMLStr | None = Field(default=None, alias="givenName")
    home_organization: PySAMLStr | None = Field(default=None, alias="schacHomeOrganization")
    home_organization_type: PySAMLStr | None = Field(default=None, alias="schacHomeOrganizationType")
    mail: PySAMLStr | None = None
    nin: PySAMLStr | None = Field(default=None, alias="norEduPersonNIN")
    organization_acronym: PySAMLStr | None = Field(default=None, alias="norEduOrgAcronym")
    organization_name: PySAMLStr | None = Field(default=None, alias="o")
    personal_identity_number: PySAMLStr | None = Field(default=None, alias="personalIdentityNumber")
    scoped_affiliation: PySAMLStr | None = Field(default=None, alias="eduPersonScopedAffiliation")
    surname: PySAMLStr | None = Field(default=None, alias="sn")
    targeted_id: PySAMLStr | None = Field(default=None, alias="eduPersonTargetedID")
    unique_id: PySAMLStr | None = Field(default=None, alias="eduPersonUniqueId")
    model_config = ConfigDict(extra="allow", populate_by_name=True)


class SessionInfo(BaseModel):
    issuer: str
    authn_info: list[AuthnInfo] = Field(default_factory=list)
    name_id: NameID
    attributes: SAMLAttributes
    # TODO: raw_assertion needed for spec compliant SubjectAssertion

    @classmethod
    def from_pysaml2(cls: type[SessionInfo], session_info: dict[str, Any]) -> SessionInfo:
        session_info["authn_info"] = [
            AuthnInfo(authn_class=item[0], authn_authority=item[1], authn_instant=item[2])
            for item in session_info["authn_info"]
        ]
        session_info["name_id"] = NameID(
            format=session_info["name_id"].format,
            name_qualifier=session_info["name_id"].name_qualifier,
            sp_name_qualifier=session_info["name_id"].sp_name_qualifier,
            sp_provided_id=session_info["name_id"].sp_provided_id,
            id=session_info["name_id"].text,
        )
        session_info["attributes"] = SAMLAttributes(**session_info["ava"])
        return cls(**session_info)


class AssertionData(BaseModel):
    session_info: SessionInfo
    authn_req_ref: AuthnRequestRef


class OutstandingQueriesCache(MongoCache):
    """
    Handles the queries that has been sent to an IdP that has not replied yet.
    """

    def __init__(
        self: Self,
        db_client: MongoClient,
        db_name: str = "auth_server",
        collection: str = "pysaml2_outstanding_queries",
        expire_after: timedelta = timedelta(hours=1),
    ) -> None:
        super().__init__(db_client=db_client, db_name=db_name, collection=collection, expire_after=expire_after)

    def _entry(self: Self, saml2_session_id: str) -> dict[str, Any] | None:
        try:
            ret = self[saml2_session_id]
        except KeyError:
            return None
        if isinstance(ret, str):
            # entries written before the IdP was stored are just the authn request reference
            return {"authn_ref": ret, "idp": None}
        assert isinstance(ret, dict)
        return ret

    def get(self: Self, saml2_session_id: str, default: str | None = None) -> str | None:  # type: ignore[override]
        """Get the authn request reference for a saml request id"""
        entry = self._entry(saml2_session_id)
        if entry is None:
            return default
        authn_ref = entry["authn_ref"]
        assert isinstance(authn_ref, str)
        return authn_ref

    def get_idp(self: Self, saml2_session_id: str) -> str | None:
        """Get the entity id of the IdP a saml request id was sent to, None if unknown"""
        entry = self._entry(saml2_session_id)
        if entry is None:
            return None
        return entry.get("idp")

    def set(self: Self, saml2_session_id: str, authn_ref: str, idp: str | None) -> None:
        self[saml2_session_id] = {"authn_ref": authn_ref, "idp": idp}

    def delete(self: Self, saml2_session_id: str) -> None:
        if saml2_session_id in self:
            del self[saml2_session_id]


class ExpectedIdPs:
    """
    Mapping view of the outstanding queries from request id to the IdP the request was sent to.

    Used as `expected_idps` for the pygamlastan client so that a response is only accepted from the IdP that
    got the request, which is needed when more than one IdP is configured.
    """

    def __init__(self: Self, outstanding_queries_cache: OutstandingQueriesCache) -> None:
        self._cache = outstanding_queries_cache

    def get(self: Self, request_id: str, default: str | None = None) -> str | None:
        return self._cache.get_idp(request_id) or default


# The pygamlastan native adapter turns any exception from the replay cache into "replay detected" (False), which
# the client reports as a verification error. A Mongo outage would then look like a bad response (400) and the
# real error is lost. The cache keeps the error here (the SAML client is called synchronously on the loop thread,
# so this is request scoped) and get_authn_response re-raises it after the client returns or fails.
_replay_backend_error: ContextVar[PyMongoError | None] = ContextVar("replay_backend_error", default=None)


class ReplayCache:
    """
    MongoDB backed replay cache for the pygamlastan client, shared by all workers.

    Implements the pygamlastan ReplayCacheProtocol: check_and_insert returns True when the id has not been seen
    (and records it until expiry) and False for a replay. The insert is atomic through a unique index, expired
    entries are removed by a TTL index (and treated as unseen even before Mongo has removed them).
    """

    def __init__(
        self: Self,
        db_client: MongoClient,
        db_name: str = "auth_server",
        collection: str = "saml_replay_cache",
    ) -> None:
        # Replay entries are written with w=majority, unlike the other caches (default write concern): an entry that
        # is only on the primary can be lost in a failover, and then a captured response or assertion could be
        # replayed against the new primary. Losing any of the other cache entries only fails or restarts a login.
        self._coll = db_client[db_name][collection].with_options(write_concern=WriteConcern(w="majority"))
        self._coll.create_index("lookup_key", unique=True)
        self._coll.create_index("expires_at", expireAfterSeconds=0)

    def check_and_insert(self: Self, id: str, expiry: datetime) -> bool:
        try:
            try:
                self._coll.insert_one({"lookup_key": id, "expires_at": expiry})
                return True
            except DuplicateKeyError:
                # the id exists, it is only a replay if the old entry has not expired yet
                res = self._coll.update_one(
                    {"lookup_key": id, "expires_at": {"$lt": utc_now()}}, {"$set": {"expires_at": expiry}}
                )
                return res.matched_count == 1
        except PyMongoError as e:
            # still fails closed (the native adapter turns the exception into a replay), but keep the real error
            logger.error(f"SAML replay cache backend error: {e!r}")
            _replay_backend_error.set(e)
            raise

    def cleanup(self: Self) -> None:
        # expired entries are removed by the TTL index
        return None


class StateCache(MongoCache):
    """
    Store state information that is needed to associate a logout request with its response.
    """

    def __init__(
        self: Self,
        db_client: MongoClient,
        db_name: str = "auth_server",
        collection: str = "pysaml2_state_cache",
        expire_after: timedelta = timedelta(days=10),
    ) -> None:
        super().__init__(db_client=db_client, db_name=db_name, collection=collection, expire_after=expire_after)


class AuthenticationRequestCache(MongoCache):
    def __init__(
        self: Self,
        db_client: MongoClient,
        db_name: str = "auth_server",
        collection: str = "saml_authentications_cache",
        expire_after: timedelta = timedelta(days=10),
    ) -> None:
        super().__init__(db_client=db_client, db_name=db_name, collection=collection, expire_after=expire_after)


@dataclass
class _SP:
    """A built SAML2SP with what it was built from, to know when it is stale"""

    config: AuthServerConfig
    sp_config: SPConfig
    saml2_sp: SAML2SP
    mongo_client: MongoClient


# One SAML2SP per process (one MongoClient, one set of caches, indexes created once)
_sp_lock = threading.Lock()
_sp: _SP | None = None


def _build_saml2_sp(config: AuthServerConfig, sp_config: SPConfig) -> _SP:
    """Blocking, creates the Mongo client and the indexes. Run it in a thread."""
    mongo_client = create_sync_mongo_client(config)
    if mongo_client is None:
        raise RuntimeError("mongo_uri is not configured")
    try:
        state_cache = StateCache(db_client=mongo_client)
        # no identity cache, the sessions are not used for anything (no single logout)
        saml2_sp = SAML2SP(
            client=Saml2Client(
                sp_config,
                state_cache=state_cache,
                identity_cache=None,
                # shared between all workers, the default in memory cache only protects a single process
                replay_cache=ReplayCache(db_client=mongo_client),
            ),
            outstanding_queries_cache=OutstandingQueriesCache(db_client=mongo_client),
            authn_req_cache=AuthenticationRequestCache(db_client=mongo_client),
            discovery_service_url=config.saml2_discovery_service_url,
            single_idp=config.saml2_single_idp,
        )
    except BaseException:
        # a failed build is never cached, do not leak its client
        mongo_client.close()
        raise
    return _SP(config=config, sp_config=sp_config, saml2_sp=saml2_sp, mongo_client=mongo_client)


def _is_current(sp: _SP | None, config: AuthServerConfig, sp_config: SPConfig) -> bool:
    # load_config and get_pysaml2_sp_config are cached, a new object means the config was cleared and reloaded
    return sp is not None and sp.config is config and sp.sp_config is sp_config


def _get_or_build_saml2_sp(config: AuthServerConfig, sp_config: SPConfig) -> SAML2SP:
    global _sp  # noqa: PLW0603
    with _sp_lock:
        if _is_current(_sp, config, sp_config):
            assert _sp is not None  # please mypy
            return _sp.saml2_sp
        built = _build_saml2_sp(config, sp_config)
        old, _sp = _sp, built
    if old is not None:
        old.mongo_client.close()
    return built.saml2_sp


def clear_saml2_sp() -> None:
    """Forget the SAML2SP and close its Mongo client. Used on shutdown and by tests when the config is changed."""
    global _sp  # noqa: PLW0603
    with _sp_lock:
        old, _sp = _sp, None
    if old is not None:
        old.mongo_client.close()


async def get_saml2_sp() -> SAML2SP | None:
    config = load_config()
    if not config.pysaml2_config_path or not config.mongo_uri:
        return None
    sp_config = get_pysaml2_sp_config(name=config.pysaml2_config_name)

    current = _sp
    if _is_current(current, config, sp_config):
        assert current is not None  # please mypy
        return current.saml2_sp
    # building blocks (index creation), keep it off the event loop. The lock makes concurrent first calls build once.
    return await asyncio.to_thread(_get_or_build_saml2_sp, config, sp_config)


COMPAT_PACKAGE = saml2_compat.__name__


@lru_cache
def saml2_compat_module_names() -> frozenset[str]:
    """Names (relative to saml2) of every module the pygamlastan compat package provides"""
    return frozenset(
        info.name.removeprefix(f"{COMPAT_PACKAGE}.")
        for info in pkgutil.walk_packages(saml2_compat.__path__, prefix=f"{COMPAT_PACKAGE}.")
    )


class UnsupportedSAML2Module(ModuleNotFoundError):
    pass


class _Saml2AliasLoader(Loader):
    def __init__(self: Self, target: str, used: set[str]) -> None:
        self.target = target
        self.used = used

    def create_module(self: Self, spec: ModuleSpec) -> ModuleType:
        self.used.add(spec.name)
        return importlib.import_module(self.target)

    def exec_module(self: Self, module: ModuleType) -> None:
        pass


class _Saml2AliasFinder(MetaPathFinder):
    """Serves `saml2` and `saml2.<submodule>` imports from the pygamlastan compat package, recording what was used"""

    def __init__(self: Self) -> None:
        self.used: set[str] = set()

    def find_spec(
        self: Self, fullname: str, path: Sequence[str] | None = None, target: ModuleType | None = None
    ) -> ModuleSpec | None:
        if fullname != "saml2" and not fullname.startswith("saml2."):
            return None
        relative = fullname.removeprefix("saml2.") if fullname != "saml2" else ""
        if relative and relative not in saml2_compat_module_names():
            raise UnsupportedSAML2Module(
                f"{fullname} is not provided by {COMPAT_PACKAGE}. The settings file imports a pysaml2 module that is "
                "not available with pygamlastan and needs to be migrated.",
                name=fullname,
            )
        target_name = f"{COMPAT_PACKAGE}.{relative}" if relative else COMPAT_PACKAGE
        spec = ModuleSpec(fullname, _Saml2AliasLoader(target_name, self.used), is_package=not relative or None)
        return spec


@contextmanager
def saml2_module_alias() -> Iterator[set[str]]:
    """
    Make `import saml2` (and `saml2.<submodule>`) resolve to the pygamlastan compat shim.

    This lets the existing settings files, that were written for pysaml2, load unchanged. The alias is only in place
    while the settings file is executed. Yields the set of saml2* module names that were really imported through the
    alias. Importing a saml2 submodule that the compat package does not have raises UnsupportedSAML2Module.
    """
    finder = _Saml2AliasFinder()
    previous = {name: mod for name, mod in sys.modules.items() if name == "saml2" or name.startswith("saml2.")}
    for name in previous:
        del sys.modules[name]
    sys.meta_path.insert(0, finder)
    try:
        yield finder.used
    finally:
        sys.meta_path.remove(finder)
        for name in [n for n in sys.modules if n == "saml2" or n.startswith("saml2.")]:
            del sys.modules[name]
        sys.modules.update(previous)


def load_sp_config(settings: dict[str, Any]) -> SPConfig:
    """
    Create an SPConfig from a pysaml2 style settings dict.

    The compat SPConfig only knows `local` and `remote` metadata sources. `mdq` sources are taken out of the settings
    and attached as on-demand sources (MDQMetadataSource) on a store that resolves entities lazily.
    """
    settings = dict(settings)
    metadata_settings = dict(settings.get("metadata", {}))
    mdq_settings = metadata_settings.pop("mdq", [])
    settings["metadata"] = metadata_settings

    conf = LazySPConfig()
    conf.load(settings)

    store = LazyMetadataStore()
    remote_settings = {str(r["url"]): r for r in metadata_settings.get("remote", [])}
    for source, local in conf.metadata.metadata.items():
        is_remote = source in remote_settings
        store.add_source(
            source,
            list(local.entities.values()),  # type: ignore[union-attr]
            deadlines=conf.source_deadlines.get(source),
            loader=partial(
                reload_metadata_source, "remote" if is_remote else "local", source, remote_settings.get(source)
            ),
        )
    if isinstance(mdq_settings, str):
        mdq_settings = [mdq_settings]
    for mdq in mdq_settings:
        if isinstance(mdq, str):
            # pysaml2 style bare url
            logger.info(f"MDQ server {mdq} configured as a bare url, use {{'url': ..., 'cert': ...}} to pin a cert")
            mdq = {"url": mdq}
        if not isinstance(mdq, dict) or not mdq.get("url"):
            raise SourceNotFound("mdq metadata entries require a url")
        logger.info(f"Using MDQ server {mdq['url']} for SAML2 metadata")
        store.add_mdq_source(MDQMetadataSource(url=str(mdq["url"]), cert=mdq.get("cert")))
    conf.metadata = store
    return conf


@lru_cache
def get_pysaml2_sp_config(name: str) -> SPConfig:
    """
    Load SAML2 config file, in the form of a Python module
    """
    config = load_config()
    spec = importlib.util.spec_from_file_location("saml2_settings", config.pysaml2_config_path)
    if spec is None:
        raise RuntimeError(f"Failed loading saml2_settings module: {config.pysaml2_config_path}")
    module = importlib.util.module_from_spec(spec)
    with saml2_module_alias() as used_aliases:
        spec.loader.exec_module(module)  # type: ignore
    if used_aliases:
        logger.warning(
            f"{config.pysaml2_config_path} imports pysaml2 ({', '.join(sorted(used_aliases))}), which is now provided "
            "by pygamlastan. Import from pygamlastan.compat.saml2 instead, the saml2 alias will be removed."
        )

    settings = module.__getattribute__(name)
    # pygamlastan defaults want_assertions_signed to False, pysaml2 defaulted both want_response_signed and
    # want_assertions_signed to True. Keep the pysaml2 defaults so a settings file written for pysaml2 is not
    # silently loosened (or tightened) by the swap. Explicit settings win.
    sp_settings = settings.setdefault("service", {}).setdefault("sp", {})
    sp_settings.setdefault("want_response_signed", True)
    sp_settings.setdefault("want_assertions_signed", True)
    if not sp_settings["want_response_signed"] and not sp_settings["want_assertions_signed"] and not config.testing:
        logger.critical(
            f"{config.pysaml2_config_path}: want_response_signed and want_assertions_signed are both False, SAML "
            "signature verification is disabled and unsigned responses are accepted. Never run like this in "
            "production."
        )
    return load_sp_config(settings)


async def prefetch_idp_metadata(saml2_sp: SAML2SP, idp_entity_id: str | None) -> None:
    """
    Warm the on-demand (MDQ) metadata for an IdP so the synchronous SAML client does not block on the fetch, and
    reload the local/remote metadata sources that are due (lookups never do I/O, see LazyMetadataStore).
    """
    store = saml2_sp.client.config.metadata
    if isinstance(store, LazyMetadataStore):
        await store.refresh_sources()
        if idp_entity_id is not None:
            await store.prefetch(idp_entity_id)


async def get_redirect_url(http_info: SAMLHttpArgs) -> str:
    """Extract the redirect URL from a pysaml2 style http_info object"""
    assert "headers" in http_info
    headers = http_info["headers"]

    assert len(headers) == 1
    header_name, header_value = headers[0]
    assert header_name == "Location"
    return header_value


async def get_authn_request(
    relay_state: str,
    authn_id: AuthnRequestRef,
    selected_idp: str | None,
    force_authn: bool = False,
    sign_alg: str | None = None,
    digest_alg: str | None = None,
    subject: Subject | None = None,
    required_loa: list[str] | None = None,
) -> SAMLHttpArgs | None:
    kwargs: dict[str, Any] = {
        "force_authn": str(force_authn).lower(),
    }
    logger.debug(f"Authn request args: {kwargs}")

    saml2_sp = await get_saml2_sp()
    if saml2_sp is None:
        return None

    # LOA
    if required_loa is not None:
        logger.info(f"Requesting AuthnContext {required_loa}")
        kwargs["requested_authn_context"] = {"authn_context_class_ref": required_loa, "comparison": "exact"}

    # the IdP the client will look up, the selected one or else the only one the settings allow
    await prefetch_idp_metadata(saml2_sp, selected_idp or saml2_sp.client.config.only_idp())
    try:
        (session_id, info) = saml2_sp.client.prepare_for_authenticate(
            entityid=selected_idp,
            relay_state=relay_state,
            binding=BINDING_HTTP_REDIRECT,
            sigalg=sign_alg,
            digest_alg=digest_alg,
            subject=subject,
            **kwargs,
        )
    except TypeError:
        logger.error("Unable to know which IdP to use")
        raise

    saml2_sp.outstanding_queries_cache.set(session_id, authn_id, idp=selected_idp or saml2_sp.client.config.only_idp())
    return info


def get_session_info(response: AuthnResponse) -> dict[str, Any]:
    """
    Get the session info dict from a response, with attribute values like pysaml2 would have given them.

    The pygamlastan compat layer keeps the whitespace around values, pysaml2 stripped the values.
    Attributes with NameID values (eduPersonTargetedID) come out without values from the compat layer. They are not
    supported and are dropped here.
    """
    session_info = response.session_info()
    session_info["ava"] = {
        name: [v.strip() if isinstance(v, str) else v for v in values]
        for name, values in session_info["ava"].items()
        if values
    }
    return session_info


async def process_assertion(saml_response: str) -> AssertionData | None:
    """
    Code to process a received SAML assertion.
    """
    saml2_sp = await get_saml2_sp()
    if saml2_sp is None:
        return None

    response, authn_ref = await get_authn_response(saml_response)
    logger.debug(f"authn response: {response}")

    if authn_ref not in saml2_sp.authn_req_cache:
        logger.info("Unknown response")
        raise BadSAMLResponse("Unknown response")

    session_info = SessionInfo.from_pysaml2(get_session_info(response))
    attributes = session_info.attributes
    # Fail closed: flows.py needs one of these to put a subject identity claim in the token. eduPersonTargetedID is
    # not supported by the pygamlastan compat layer, so an IdP releasing only that ends up here.
    if not (attributes.eppn or attributes.unique_id or attributes.targeted_id):
        logger.error(f"SAML assertion from {session_info.issuer} has no supported identity attribute")
        raise BadSAMLResponse(
            "SAML assertion has no supported identity attribute (eduPersonPrincipalName, eduPersonUniqueId)"
        )
    assertion_data = AssertionData(session_info=session_info, authn_req_ref=authn_ref)
    # Fix eduPersonTargetedID (only reached if a compat version delivers a value)
    targeted_id_value = assertion_data.session_info.attributes.targeted_id
    if targeted_id_value:
        issuer_entityid = assertion_data.session_info.issuer
        sp_entityid = saml2_sp.client.config.entityid
        assertion_data.session_info.attributes.targeted_id = f"{issuer_entityid}!{sp_entityid}!{targeted_id_value}"
    return assertion_data


# message start of the StatusError that pygamlastan raises when the response can not be decoded or parsed
MALFORMED_RESPONSE_PREFIX = "could not parse SAML response"
# message start of the ValueError that the compat client raises when it can not tell which IdP a request went to
# (more than one IdP and an outstanding query without a stored IdP), that is a response we can not accept
UNKNOWN_EXPECTED_IDP_PREFIX = "Cannot determine the IdP targeted by this outstanding request"


def _peek_response(raw_response: str) -> tuple[str | None, str | None]:
    """
    Best effort read of InResponseTo and Issuer from an unverified response.

    Only used to know what metadata to prefetch, the values are never trusted.
    """
    try:
        parsed = pg_xml.parse_response(base64.b64decode(raw_response).decode("utf-8"))
        issuer = parsed.issuer.value if parsed.issuer is not None else None
        return parsed.in_response_to, issuer
    except Exception:
        return None, None


def _parse_authn_response(saml2_sp: SAML2SP, raw_response: str) -> AuthnResponse:
    """
    Run the synchronous SAML client, and re-raise a Mongo error that the replay cache hit during validation.

    The error is re-raised whatever the client did with it (it is normally reported as a verification error), so the
    router can answer 503 for a backend outage and not 400 for a bad response. The request is still rejected.
    """
    _replay_backend_error.set(None)
    try:
        response = saml2_sp.client.parse_authn_request_response(
            raw_response,
            BINDING_HTTP_POST,
            saml2_sp.outstanding_queries_cache,  # type: ignore[arg-type]
            expected_idps=ExpectedIdPs(saml2_sp.outstanding_queries_cache),
        )
    except Exception:
        if (backend_error := _replay_backend_error.get()) is not None:
            raise backend_error from None
        raise
    if (backend_error := _replay_backend_error.get()) is not None:
        raise backend_error
    return response


async def get_authn_response(raw_response: str) -> tuple[AuthnResponse, AuthnRequestRef]:
    """
    Check a SAML response and return the response.

    The response can be used to retrieve a session_info dict.

    Example session_info:

    {'authn_info': [('urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport', [],
                     '2019-06-17T00:00:01Z')],
     'ava': {'eduPersonPrincipalName': ['eppn@eduid.se'],
             'eduidIdPCredentialsUsed': ['...']},
     'came_from': 'https://dashboard.eduid.se/profile/personaldata',
     'issuer': 'https://login.idp.eduid.se/idp.xml',
     'name_id': <saml2.saml.NameID object>,
     'not_on_or_after': 156000000,
     'session_index': 'id-foo'}
    """
    saml2_sp = await get_saml2_sp()
    if saml2_sp is None:
        raise RuntimeError("SAML SP not configured, this should have been caught earlier")

    # make sure the metadata for the IdP that got the request is available before the synchronous client needs it
    request_id, unverified_issuer = _peek_response(raw_response)
    expected_idp = saml2_sp.outstanding_queries_cache.get_idp(request_id) if request_id is not None else None
    if expected_idp is None:
        # outstanding query without a stored IdP (legacy) or a single IdP setup, the client will find the IdP from the
        # settings or the response. Warm the Issuer of the response, but only when the response answers a request
        # we really sent and only for an IdP the settings allow. An unsolicited response or a made up Issuer must not
        # cause outbound MDQ requests (the client rejects those without network I/O). This only fills the cache, the
        # signature and expected_idps checks in the client decide what is accepted.
        allowed_idps = saml2_sp.client.config.idp
        known_request = request_id is not None and saml2_sp.outstanding_queries_cache.get(request_id) is not None
        if known_request and unverified_issuer is not None and (not allowed_idps or unverified_issuer in allowed_idps):
            expected_idp = unverified_issuer
        else:
            expected_idp = saml2_sp.client.config.only_idp()
    await prefetch_idp_metadata(saml2_sp, expected_idp)

    try:
        # process the authentication response
        response = _parse_authn_response(saml2_sp, raw_response)
    except SignatureError as e:
        # needs to be before AssertionError as SignatureError is a subclass
        logger.error(f"SAML response signature is invalid: {repr(e)}")
        raise BadSAMLResponse("SAML response signature is invalid")
    except AssertionError:
        logger.error("SAML response is not verified")
        raise BadSAMLResponse("SAML response is not verified")
    except UnsolicitedResponse:
        logger.error("Unsolicited SAML response")
        # Extra debug to try and find the cause for some of these that seem to be incorrect
        logger.debug(f"Outstanding queries cache: {saml2_sp.outstanding_queries_cache}")
        logger.debug(f"Outstanding queries: {saml2_sp.outstanding_queries_cache.items()}")
        raise BadSAMLResponse("Unsolicited SAML response")
    except StatusError as e:
        if str(e).startswith(MALFORMED_RESPONSE_PREFIX):
            # not a status from the IdP, the response could not be decoded or parsed
            logger.error(f"SAML response is not correctly formatted: {repr(e)}")
            raise BadSAMLResponse("SAML response is not correctly formatted")
        logger.error(f"SAML response was a failure: {repr(e)}")
        raise e
    except MissingKey as e:
        # no key to verify with for the IdP
        logger.error(f"SAML response could not be verified: {repr(e)}")
        raise BadSAMLResponse("SAML response is not verified")
    except ValueError as e:
        # Only the known input case is a client error. Any other ValueError is a config or programming fault: log
        # the traceback and raise SAMLServerError (HTTP 500 with a constant detail).
        if str(e).startswith(UNKNOWN_EXPECTED_IDP_PREFIX):
            logger.error(f"SAML response could not be verified: {repr(e)}")
            raise BadSAMLResponse("SAML response is not verified")
        logger.exception("unexpected ValueError while processing SAML response")
        raise SAMLServerError("SAML response processing failed") from e
    except SAMLError as e:
        logger.error(f"SAML response could not be processed: {repr(e)}")
        raise BadSAMLResponse("SAML response could not be processed")

    if response is None:
        logger.error("SAML response is None")
        raise BadSAMLResponse("No SAML authn response")

    session_id = response.session_id()
    if session_id is None:
        logger.error("SAML response without InResponseTo")
        raise BadSAMLResponse("Unsolicited SAML response")
    authn_reqref = saml2_sp.outstanding_queries_cache.get(session_id)
    if authn_reqref is None:
        logger.error(f"No outstanding query for {session_id}")
        raise BadSAMLResponse("Unsolicited SAML response")
    authn_reqref = AuthnRequestRef(authn_reqref)
    saml2_sp.outstanding_queries_cache.delete(session_id)

    logger.debug(
        f"Response {session_id}, request reference {authn_reqref}\n"
        f"session info:\n{pprint.pformat(response.session_info())}\n\n"
    )

    return response, authn_reqref
