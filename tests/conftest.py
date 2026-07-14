"""Shared test fixtures."""

from __future__ import annotations

import json

import pytest


# --------------------------------------------------------------------------- #
# Agent-scanner test helpers (mock LLM + mock GraphQL client)
# --------------------------------------------------------------------------- #

class Msg:
    """A stand-in for a LangChain message — only ``.content`` is read by the loop."""

    def __init__(self, content: str) -> None:
        self.content = content


def scripted_llm(actions):
    """Build a callable that returns one Msg(json) per call, cycling the LAST action once the
    script is exhausted (so a run that takes extra steps doesn't crash). Monkeypatch this over
    ``gradientql.scanner.loop.invoke_with_circuit_breaker``: it ignores (llm, prompt)."""
    encoded = [Msg(a if isinstance(a, str) else json.dumps(a)) for a in actions]
    state = {"i": 0}

    def _invoke(_llm, _prompt, **_kwargs):
        i = state["i"]
        state["i"] = i + 1
        return encoded[i] if i < len(encoded) else encoded[-1]

    return _invoke


class MockClient:
    """A scripted GraphQL client. ``responses`` maps a substring-of-the-query -> response dict;
    the first matching key wins, else ``default`` is returned. Records every call."""

    def __init__(self, responses=None, default=None, introspection=None):
        self.responses = responses or {}
        self.default = default or {"data": None, "errors": [], "_status_code": 200}
        self.introspection = introspection
        self.session = None
        self.calls = []  # (query, variables, extra_headers)

    def execute(self, query, variables=None, extra_headers=None):
        self.calls.append((query, variables, dict(extra_headers or {})))
        for key, resp in self.responses.items():
            if key in query:
                return resp
        return self.default

    def introspect(self):
        return self.introspection or {"data": None, "errors": [{"message": "no introspection"}]}


@pytest.fixture(scope="session")
def dvga_url() -> str:
    """URL for the Damn Vulnerable GraphQL Application."""
    return "http://localhost:5013/graphql"


@pytest.fixture()
def sample_settings() -> dict:
    """Minimal settings dict for testing."""
    return {
        "target": {
            "url": "http://localhost:5013/graphql",
            "headers": {},
        },
        "llm": {
            "provider": "openrouter",
            "base_url": "https://openrouter.ai/api/v1",
            "api_key_env": "OPENROUTER_API_KEY",
            "api_key": "test-key",
            "generation_model": "moonshotai/kimi-k2.5",
            "analysis_model": "google/gemini-2.5-flash",
            "temperature": 0.7,
        },
        "scanner": {
            "budget": 5,
            "max_depth": 5,
        },
        "embeddings": {
            "model": "all-MiniLM-L6-v2",
        },
    }


@pytest.fixture()
def sample_introspection_result() -> dict:
    """A minimal introspection result for testing schema parsing."""
    return {
        "data": {
            "__schema": {
                "queryType": {"name": "Query"},
                "mutationType": {"name": "Mutation"},
                "subscriptionType": None,
                "types": [
                    {
                        "kind": "OBJECT",
                        "name": "Query",
                        "description": None,
                        "fields": [
                            {
                                "name": "pastes",
                                "description": "Returns all pastes",
                                "args": [
                                    {
                                        "name": "public",
                                        "description": None,
                                        "type": {
                                            "kind": "SCALAR",
                                            "name": "Boolean",
                                            "ofType": None,
                                        },
                                        "defaultValue": None,
                                    },
                                    {
                                        "name": "limit",
                                        "description": None,
                                        "type": {
                                            "kind": "SCALAR",
                                            "name": "Int",
                                            "ofType": None,
                                        },
                                        "defaultValue": None,
                                    },
                                ],
                                "type": {
                                    "kind": "LIST",
                                    "name": None,
                                    "ofType": {
                                        "kind": "OBJECT",
                                        "name": "PasteObject",
                                        "ofType": None,
                                    },
                                },
                                "isDeprecated": False,
                                "deprecationReason": None,
                            },
                            {
                                "name": "paste",
                                "description": "Returns a paste by ID",
                                "args": [
                                    {
                                        "name": "pId",
                                        "description": None,
                                        "type": {
                                            "kind": "NON_NULL",
                                            "name": None,
                                            "ofType": {
                                                "kind": "SCALAR",
                                                "name": "Int",
                                                "ofType": None,
                                            },
                                        },
                                        "defaultValue": None,
                                    },
                                ],
                                "type": {
                                    "kind": "OBJECT",
                                    "name": "PasteObject",
                                    "ofType": None,
                                },
                                "isDeprecated": False,
                                "deprecationReason": None,
                            },
                        ],
                        "inputFields": None,
                        "interfaces": [],
                        "enumValues": None,
                        "possibleTypes": None,
                    },
                    {
                        "kind": "OBJECT",
                        "name": "Mutation",
                        "description": None,
                        "fields": [
                            {
                                "name": "createPaste",
                                "description": "Create a new paste",
                                "args": [
                                    {
                                        "name": "title",
                                        "description": None,
                                        "type": {
                                            "kind": "NON_NULL",
                                            "name": None,
                                            "ofType": {
                                                "kind": "SCALAR",
                                                "name": "String",
                                                "ofType": None,
                                            },
                                        },
                                        "defaultValue": None,
                                    },
                                    {
                                        "name": "content",
                                        "description": None,
                                        "type": {
                                            "kind": "SCALAR",
                                            "name": "String",
                                            "ofType": None,
                                        },
                                        "defaultValue": None,
                                    },
                                ],
                                "type": {
                                    "kind": "OBJECT",
                                    "name": "PasteObject",
                                    "ofType": None,
                                },
                                "isDeprecated": False,
                                "deprecationReason": None,
                            },
                        ],
                        "inputFields": None,
                        "interfaces": [],
                        "enumValues": None,
                        "possibleTypes": None,
                    },
                    {
                        "kind": "OBJECT",
                        "name": "PasteObject",
                        "description": None,
                        "fields": [
                            {
                                "name": "id",
                                "description": None,
                                "args": [],
                                "type": {"kind": "SCALAR", "name": "Int", "ofType": None},
                                "isDeprecated": False,
                                "deprecationReason": None,
                            },
                            {
                                "name": "title",
                                "description": None,
                                "args": [],
                                "type": {"kind": "SCALAR", "name": "String", "ofType": None},
                                "isDeprecated": False,
                                "deprecationReason": None,
                            },
                            {
                                "name": "content",
                                "description": None,
                                "args": [],
                                "type": {"kind": "SCALAR", "name": "String", "ofType": None},
                                "isDeprecated": False,
                                "deprecationReason": None,
                            },
                        ],
                        "inputFields": None,
                        "interfaces": [],
                        "enumValues": None,
                        "possibleTypes": None,
                    },
                    {
                        "kind": "SCALAR",
                        "name": "Boolean",
                        "description": None,
                        "fields": None,
                        "inputFields": None,
                        "interfaces": None,
                        "enumValues": None,
                        "possibleTypes": None,
                    },
                    {
                        "kind": "SCALAR",
                        "name": "Int",
                        "description": None,
                        "fields": None,
                        "inputFields": None,
                        "interfaces": None,
                        "enumValues": None,
                        "possibleTypes": None,
                    },
                    {
                        "kind": "SCALAR",
                        "name": "String",
                        "description": None,
                        "fields": None,
                        "inputFields": None,
                        "interfaces": None,
                        "enumValues": None,
                        "possibleTypes": None,
                    },
                    {
                        "kind": "OBJECT",
                        "name": "__Schema",
                        "description": None,
                        "fields": [],
                        "inputFields": None,
                        "interfaces": [],
                        "enumValues": None,
                        "possibleTypes": None,
                    },
                ],
                "directives": [],
            }
        },
        "_status_code": 200,
    }
