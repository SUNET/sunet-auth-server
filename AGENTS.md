# AGENTS.md - AI Coding Agent Guidelines

This document provides instructions for AI coding agents working in this repository.

## Project Overview

**SUNET Auth Server** - A production-ready GNAP (Grant Negotiation and Authorization Protocol, RFC 9635) authentication server implementation for the eduID IAM suite.

- **Language:** Python 3.11+
- **Framework:** FastAPI (ASGI)
- **Database:** MongoDB (async via motor)
- **Key Libraries:** pydantic, jwcrypto, pysaml2, aiohttp

## Build/Test/Lint Commands

### Testing

```bash
# Run all tests with debug logging
make test

# Run specific test file
pytest src/auth_server/tests/test_app.py --log-cli-level DEBUG

# Run specific test class
pytest src/auth_server/tests/test_app.py::TestAuthServer --log-cli-level DEBUG

# Run single test method
pytest src/auth_server/tests/test_app.py::TestAuthServer::test_transaction_test_mode --log-cli-level DEBUG

# Run tests matching a pattern
pytest -k "test_transaction" --log-cli-level DEBUG
```

### Linting and Formatting

```bash
# Format code (sort imports, remove unused imports, reformat)
make reformat

# Type checking with mypy
make typecheck
```

### Dependency Management

```bash
# Sync production dependencies
make sync_deps

# Sync development dependencies
make dev_sync_deps

# Update/recompile all requirements files
make update_deps
```

Uses `uv` for fast dependency management. Dependencies are pinned with hashes in `requirements.txt`.

## Project Structure

```
src/auth_server/
├── api.py              # FastAPI app initialization
├── config.py           # Configuration (pydantic-settings)
├── context.py          # Request context handling
├── flows.py            # Authentication flow implementations
├── middleware.py       # JOSE middleware for JWS requests
├── models/             # Pydantic data models
│   ├── gnap.py         # GNAP protocol models (RFC 9635)
│   ├── jose.py         # JWK, JWS, JWT models
│   └── claims.py       # JWT claims models
├── routers/            # FastAPI route handlers
│   ├── root.py         # /transaction, /continue, /.well-known/*
│   ├── interaction.py  # User interaction endpoints
│   └── saml2_sp.py     # SAML2 SP endpoints
├── proof/              # Proof verification (mTLS, JWS, JWSD)
├── db/                 # Database layer (MongoDB)
└── tests/              # Test suite
    ├── test_app.py     # Main application tests
    └── data/           # Test fixtures
```

## Code Style Guidelines

### File Header

Every source file should include the author attribution:

```python
__author__ = "lundberg"
```

### Imports Organization

Imports are sorted by ruff in this order:
1. Standard library
2. Third-party packages
3. Local application imports

```python
from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from typing import Any, Self

from fastapi import HTTPException
from jwcrypto import jwt
from pydantic import BaseModel, Field

from auth_server.config import AuthServerConfig
from auth_server.models.gnap import GrantRequest, GrantResponse
```

### Formatting

- **Line length:** 120 characters
- **Target Python:** 3.11+
- **Formatter:** ruff format

### Ruff Lint Rules

From `ruff.toml`:
- E, F, W: pycodestyle and pyflakes
- I: isort (import sorting)
- ASYNC: async/await issues
- UP: pyupgrade
- ANN: type annotations
- PL: pylint subset

### Type Annotations

- **All functions must have type hints** (enforced by ruff ANN rules)
- Use `Self` from typing for self-referencing return types
- Use modern union syntax: `str | None` (not `Optional[str]`)
- Use `list[str]` not `List[str]`

```python
def load_config() -> AuthServerConfig:
    ...

async def transaction(self: Self) -> GrantResponse | None:
    ...

class Key(GnapBaseModel):
    jwk: ECJWK | RSAJWK | SymmetricJWK | None = None
```

### Naming Conventions

- **Classes:** PascalCase (`AuthServer`, `GrantRequest`, `BaseAuthFlow`)
- **Functions/methods:** snake_case (`load_config`, `get_signing_key`)
- **Private methods:** underscore prefix (`_run_steps`, `_clear_lru_cache`)
- **Constants:** SCREAMING_SNAKE_CASE
- **Enums:** PascalCase class, SCREAMING_SNAKE_CASE or PascalCase values

### Pydantic Models

Base model for GNAP protocol models:

```python
class GnapBaseModel(BaseModel):
    model_config = ConfigDict(populate_by_name=True)
```

Use Field aliases for JSON compatibility:

```python
cert_S256: str | None = Field(default=None, alias="cert#S256")
```

### Error Handling

Custom exceptions for flow control in `flows.py`:

```python
class NextFlowException(HTTPException):
    """Skip to next authentication flow"""
    pass

class InteractionNeededException(HTTPException):
    """Pause flow for user interaction"""
    pass

class StopTransactionException(HTTPException):
    """Return error to client"""
    pass
```

Configuration errors:

```python
class ConfigurationError(Exception):
    pass
```

### Logging

```python
import logging
logger = logging.getLogger(__name__)

# Usage
logger.debug(f"key reference: {key_id}")
logger.info(f"flow {auth_flow_name} returned GrantResponse")
logger.error(f"transaction stopped: {e.detail}")
```

### Async Patterns

- All HTTP handlers are `async def`
- Use `aiohttp.ClientSession` for async HTTP requests
- MongoDB access via motor (async driver)
- Use `@lru_cache` for configuration caching

### Testing Patterns

Tests use `unittest.TestCase` with `starlette.testclient.TestClient`:

```python
class TestAuthServer(TestCase):
    def setUp(self: Self) -> None:
        self.datadir = Path(__file__).with_name("data")
        self.mongo_db = MongoTemporaryInstance.get_instance()
        # ...

    def test_something(self: Self) -> None:
        # Test implementation
        pass
```

- MongoDB test instance via `MongoTemporaryInstance` (Docker-based)
- Mock async HTTP calls with `unittest.mock.AsyncMock`
- Test data stored in `src/auth_server/tests/data/`

## Architecture Notes

### Flow-based Authentication

The server runs through configured authentication flows until one succeeds:
- `TestFlow` - Testing purposes
- `ConfigFlow` - Pre-configured client keys
- `CAFlow` - Certificate Authority validation
- `MDQFlow` - SAML Metadata Query
- `TLSFEDFlow` - TLS Federation
- `InteractionFlow` - User interaction (SAML, etc.)

### Transaction States

`PROCESSING` -> `PENDING` -> `APPROVED` -> `FINALIZED`

### Abstract Base Class Pattern

`BaseAuthFlow` defines the interface, specific flows inherit and override:

```python
class BaseAuthFlow(ABC):
    @abstractmethod
    async def transaction(self: Self) -> GrantResponse | None:
        ...
```
