#!/usr/bin/env python3
from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi.testclient import TestClient

from src.api.main import app

ROOT = Path(__file__).resolve().parents[1]
PY_OUT = ROOT / "sdk/python/greenlight_client.py"
TS_OUT = ROOT / "sdk/typescript/greenlightClient.ts"

METHODS = ["get", "post", "put", "patch", "delete"]


def _path_params(path: str) -> List[str]:
    return re.findall(r"\{([^}]+)\}", path)


def _to_py_path_template(path: str) -> str:
    return re.sub(r"\{([^}]+)\}", r"{\1}", path)


def _to_ts_path_template(path: str) -> str:
    return re.sub(r"\{([^}]+)\}", r"${encodeURIComponent(String(args.\1))}", path)


def _schema_ref_name(node: Optional[Dict[str, Any]]) -> Optional[str]:
    if not isinstance(node, dict):
        return None
    ref = node.get("$ref")
    if isinstance(ref, str) and ref.startswith("#/components/schemas/"):
        return ref.split("/")[-1]
    return None


def _response_ref_name(operation: Dict[str, Any]) -> Optional[str]:
    responses = operation.get("responses", {})
    for code in ("200", "201", "202", "default"):
        if code not in responses:
            continue
        schema = responses[code].get("content", {}).get("application/json", {}).get("schema")
        ref = _schema_ref_name(schema)
        if ref:
            return ref
    return None


def _paginate_item_types(response_ref: str, schemas: Dict[str, Any]) -> Optional[Dict[str, str]]:
    response_schema = schemas.get(response_ref)
    if not isinstance(response_schema, dict):
        return None
    data_ref = _schema_ref_name((response_schema.get("properties") or {}).get("data"))
    if not data_ref:
        return None
    data_schema = schemas.get(data_ref)
    if not isinstance(data_schema, dict):
        return None
    data_props = data_schema.get("properties") or {}
    if "items" not in data_props:
        return None
    if "limit" not in data_props or "offset" not in data_props:
        return None
    items_node = data_props.get("items")
    if not isinstance(items_node, dict) or items_node.get("type") != "array":
        return None
    item_schema = items_node.get("items")
    return {
        "item_type_py": _map_py_type(item_schema, schemas),
        "item_type_ts": _map_ts_type(item_schema, schemas),
    }


def _map_ts_type(node: Optional[Dict[str, Any]], schemas: Dict[str, Any]) -> str:
    if not isinstance(node, dict):
        return "unknown"

    ref = _schema_ref_name(node)
    if ref:
        return ref

    if "anyOf" in node:
        parts = [_map_ts_type(part, schemas) for part in node["anyOf"]]
        return " | ".join(dict.fromkeys(parts)) or "unknown"

    if "enum" in node and node.get("type") == "string":
        vals = [repr(v).replace("'", '"') for v in node.get("enum", [])]
        return " | ".join(vals) if vals else "string"

    t = node.get("type")
    if t == "string":
        return "string"
    if t in {"integer", "number"}:
        return "number"
    if t == "boolean":
        return "boolean"
    if t == "array":
        inner = _map_ts_type(node.get("items"), schemas)
        if "|" in inner and not inner.startswith("("):
            inner = f"({inner})"
        return f"{inner}[]"
    if t == "object":
        props = node.get("properties")
        if isinstance(props, dict) and props:
            required = set(node.get("required") or [])
            fields = []
            for name, sub in props.items():
                opt = "" if name in required else "?"
                fields.append(f"{name}{opt}: {_map_ts_type(sub, schemas)}")
            return "{ " + "; ".join(fields) + " }"
        addl = node.get("additionalProperties")
        if isinstance(addl, dict):
            return f"Record<string, {_map_ts_type(addl, schemas)}>"
        return "Record<string, unknown>"

    return "unknown"


def _map_py_type(node: Optional[Dict[str, Any]], schemas: Dict[str, Any]) -> str:
    if not isinstance(node, dict):
        return "Any"

    ref = _schema_ref_name(node)
    if ref:
        return ref

    if "anyOf" in node:
        parts = [_map_py_type(part, schemas) for part in node["anyOf"]]
        return f"Union[{', '.join(dict.fromkeys(parts))}]"

    if "enum" in node and node.get("type") == "string":
        vals = ", ".join([repr(v) for v in node.get("enum", [])])
        return f"Literal[{vals}]" if vals else "str"

    t = node.get("type")
    if t == "string":
        return "str"
    if t == "integer":
        return "int"
    if t == "number":
        return "float"
    if t == "boolean":
        return "bool"
    if t == "array":
        return f"List[{_map_py_type(node.get('items'), schemas)}]"
    if t == "object":
        addl = node.get("additionalProperties")
        if isinstance(addl, dict):
            return f"Dict[str, {_map_py_type(addl, schemas)}]"
        return "Dict[str, Any]"

    return "Any"


def _render_ts_models(schemas: Dict[str, Any]) -> List[str]:
    out: List[str] = []
    for name, schema in sorted(schemas.items()):
        if not isinstance(schema, dict):
            continue
        if schema.get("type") == "object":
            props = schema.get("properties") or {}
            required = set(schema.get("required") or [])
            out.append(f"export interface {name} {{")
            for prop, sub in props.items():
                opt = "" if prop in required else "?"
                out.append(f"  {prop}{opt}: {_map_ts_type(sub, schemas)};")
            if not props and schema.get("additionalProperties"):
                out.append("  [key: string]: unknown;")
            out.append("}")
            out.append("")
        else:
            out.append(f"export type {name} = {_map_ts_type(schema, schemas)};")
            out.append("")
    return out


def _render_py_models(schemas: Dict[str, Any]) -> List[str]:
    out: List[str] = []
    for name, schema in sorted(schemas.items()):
        if not isinstance(schema, dict):
            continue
        if schema.get("type") == "object":
            props = schema.get("properties") or {}
            required = set(schema.get("required") or [])
            out.append(f"class {name}(TypedDict):")
            if not props:
                out.append("    pass")
            else:
                for prop, sub in props.items():
                    typ = _map_py_type(sub, schemas)
                    if prop in required:
                        out.append(f"    {prop}: {typ}")
                    else:
                        out.append(f"    {prop}: NotRequired[{typ}]")
            out.append("")
        else:
            out.append(f"{name}: TypeAlias = {_map_py_type(schema, schemas)}")
            out.append("")
    return out


def _operations(schema: Dict[str, Any]) -> List[Dict[str, Any]]:
    ops: List[Dict[str, Any]] = []
    schemas = schema.get("components", {}).get("schemas", {})
    for path, methods in schema.get("paths", {}).items():
        if not path.startswith("/api/"):
            continue
        for method in METHODS:
            op = methods.get(method)
            if not op:
                continue
            operation_id = op.get("operationId")
            if not operation_id:
                continue

            request_schema = op.get("requestBody", {}).get("content", {}).get("application/json", {}).get("schema")
            request_ref = _schema_ref_name(request_schema)
            response_ref = _response_ref_name(op)
            paginator = _paginate_item_types(response_ref, schemas) if response_ref else None

            ops.append(
                {
                    "operation_id": operation_id,
                    "method": method.upper(),
                    "path": path,
                    "path_params": _path_params(path),
                    "request_type_py": request_ref or "Dict[str, Any]",
                    "request_type_ts": request_ref or "Record<string, unknown>",
                    "response_type_py": response_ref or "ApiResponse",
                    "response_type_ts": response_ref or "ApiResponse",
                    "paginator": paginator,
                }
            )
    return sorted(ops, key=lambda x: x["operation_id"])


def _render_python_client(ops: List[Dict[str, Any]], schemas: Dict[str, Any]) -> str:
    lines = [
        '"""Generated client baseline for Greenlight API. Do not edit by hand."""',
        "from __future__ import annotations",
        "",
        "import json",
        "import time",
        "import urllib.error",
        "import urllib.parse",
        "import urllib.request",
        "from typing import Any, Callable, Dict, List, Literal, NotRequired, Optional, TypeAlias, TypedDict, Union",
        "",
        "ApiResponse: TypeAlias = Dict[str, Any]",
        "",
    ]
    lines.extend(_render_py_models(schemas))
    lines.extend(
        [
            "class GreenlightApiError(Exception):",
            "    def __init__(",
            "        self,",
            "        *,",
            "        status_code: Optional[int],",
            "        code: str,",
            "        message: str,",
            "        request_id: Optional[str] = None,",
            "        details: Optional[Any] = None,",
            "    ):",
            "        super().__init__(message)",
            "        self.status_code = status_code",
            "        self.code = code",
            "        self.message = message",
            "        self.request_id = request_id",
            "        self.details = details",
            "",
            "class GreenlightClient:",
            "    def __init__(self, base_url: str, api_key: str, timeout: int = 30, max_retries: int = 3, backoff_base_seconds: float = 0.25, logger: Optional[Callable[[Dict[str, Any]], None]] = None):",
            "        self.base_url = base_url.rstrip('/')",
            "        self.api_key = api_key",
            "        self.timeout = timeout",
            "        self.max_retries = max_retries",
            "        self.backoff_base_seconds = backoff_base_seconds",
            "        self.logger = logger",
            "",
            "    def _should_retry_status(self, status_code: int) -> bool:",
            "        return status_code == 429 or 500 <= status_code < 600",
            "",
            "    def _sleep_backoff(self, attempt: int) -> None:",
            "        delay = self.backoff_base_seconds * (2 ** attempt)",
            "        time.sleep(delay)",
            "",
            "    def _build_api_error_from_http_error(self, exc: urllib.error.HTTPError) -> GreenlightApiError:",
            "        request_id = exc.headers.get('X-Request-Id') if exc.headers else None",
            "        raw = ''",
            "        try:",
            "            raw = exc.read().decode('utf-8', errors='replace')",
            "        except Exception:",
            "            raw = ''",
            "        code = 'HTTP_ERROR'",
            "        message = f'HTTP {exc.code}'",
            "        details: Optional[Any] = None",
            "        if raw:",
            "            try:",
            "                parsed = json.loads(raw)",
            "                if isinstance(parsed, dict):",
            "                    err = parsed.get('error')",
            "                    if isinstance(err, dict):",
            "                        code = str(err.get('code') or code)",
            "                        message = str(err.get('message') or message)",
            "                        details = err.get('details')",
            "            except Exception:",
            "                message = raw[:500]",
            "        return GreenlightApiError(status_code=exc.code, code=code, message=message, request_id=request_id, details=details)",
            "",
            "    def _build_api_error_from_url_error(self, exc: urllib.error.URLError, request_id: Optional[str] = None) -> GreenlightApiError:",
            "        reason = getattr(exc, 'reason', None)",
            "        message = str(reason) if reason is not None else str(exc)",
            "        return GreenlightApiError(status_code=None, code='NETWORK_ERROR', message=message, request_id=request_id)",
            "",
            "    def _emit_log(self, event: Dict[str, Any], logger_override: Optional[Callable[[Dict[str, Any]], None]] = None) -> None:",
            "        log_fn = logger_override or self.logger",
            "        if not log_fn:",
            "            return",
            "        try:",
            "            log_fn(event)",
            "        except Exception:",
            "            pass",
            "",
            "    def _request(",
            "        self,",
            "        method: str,",
            "        path: str,",
            "        *,",
            "        params: Optional[Dict[str, Any]] = None,",
            "        body: Optional[Any] = None,",
            "        timeout: Optional[int] = None,",
            "        max_retries: Optional[int] = None,",
            "        backoff_base_seconds: Optional[float] = None,",
            "        logger: Optional[Callable[[Dict[str, Any]], None]] = None,",
            "    ) -> Any:",
            "        url = f\"{self.base_url}{path}\"",
            "        if params:",
            "            query = urllib.parse.urlencode(params, doseq=True)",
            "            url = f\"{url}?{query}\"",
            "        payload = None",
            "        headers = {",
            "            'Authorization': f'Bearer {self.api_key}',",
            "            'Content-Type': 'application/json',",
            "        }",
            "        if body is not None:",
            "            payload = json.dumps(body).encode('utf-8')",
            "        effective_timeout = timeout if timeout is not None else self.timeout",
            "        effective_retries = max_retries if max_retries is not None else self.max_retries",
            "        effective_backoff = backoff_base_seconds if backoff_base_seconds is not None else self.backoff_base_seconds",
            "        last_exc: Optional[Exception] = None",
            "        last_request_id: Optional[str] = None",
            "        attempts = max(effective_retries, 0) + 1",
            "        for attempt in range(attempts):",
            "            attempt_start = time.perf_counter()",
            "            req = urllib.request.Request(url=url, data=payload, headers=headers, method=method)",
            "            try:",
            "                with urllib.request.urlopen(req, timeout=effective_timeout) as resp:",
                    "                    raw = resp.read().decode('utf-8')",
            "                    parsed = json.loads(raw) if raw else {}",
            "                    request_id = resp.headers.get('X-Request-Id') if resp.headers else None",
            "                    last_request_id = request_id or last_request_id",
            "                    self._emit_log({",
            "                        'event': 'http_request',",
            "                        'method': method,",
            "                        'path': path,",
            "                        'status_code': getattr(resp, 'status', None),",
            "                        'duration_ms': round((time.perf_counter() - attempt_start) * 1000, 2),",
            "                        'attempt': attempt + 1,",
            "                        'request_id': request_id,",
            "                        'has_body': body is not None,",
            "                        'query_keys': sorted((params or {}).keys()),",
            "                    }, logger_override=logger)",
            "                    return parsed",
            "            except urllib.error.HTTPError as exc:",
            "                last_exc = exc",
            "                api_err = self._build_api_error_from_http_error(exc)",
            "                last_request_id = api_err.request_id or last_request_id",
            "                self._emit_log({",
            "                    'event': 'http_error',",
            "                    'method': method,",
            "                    'path': path,",
            "                    'status_code': exc.code,",
            "                    'duration_ms': round((time.perf_counter() - attempt_start) * 1000, 2),",
            "                    'attempt': attempt + 1,",
            "                    'request_id': api_err.request_id,",
            "                    'error_code': api_err.code,",
            "                    'has_body': body is not None,",
            "                    'query_keys': sorted((params or {}).keys()),",
            "                }, logger_override=logger)",
            "                if attempt + 1 < attempts and self._should_retry_status(exc.code):",
            "                    time.sleep(effective_backoff * (2 ** attempt))",
            "                    continue",
            "                raise api_err",
            "            except urllib.error.URLError as exc:",
            "                last_exc = exc",
            "                api_err = self._build_api_error_from_url_error(exc, request_id=last_request_id)",
            "                self._emit_log({",
            "                    'event': 'network_error',",
            "                    'method': method,",
            "                    'path': path,",
            "                    'status_code': None,",
            "                    'duration_ms': round((time.perf_counter() - attempt_start) * 1000, 2),",
            "                    'attempt': attempt + 1,",
            "                    'request_id': api_err.request_id,",
            "                    'error_code': api_err.code,",
            "                    'has_body': body is not None,",
            "                    'query_keys': sorted((params or {}).keys()),",
            "                }, logger_override=logger)",
            "                if attempt + 1 < attempts:",
            "                    time.sleep(effective_backoff * (2 ** attempt))",
            "                    continue",
            "                raise api_err",
            "        if last_exc:",
            "            if isinstance(last_exc, urllib.error.HTTPError):",
            "                raise self._build_api_error_from_http_error(last_exc)",
            "            if isinstance(last_exc, urllib.error.URLError):",
            "                raise self._build_api_error_from_url_error(last_exc, request_id=last_request_id)",
            "            raise GreenlightApiError(status_code=None, code='REQUEST_FAILED', message=str(last_exc), request_id=last_request_id)",
            "        raise RuntimeError('Request failed without explicit exception')",
        ]
    )

    for op in ops:
        op_id = op["operation_id"]
        method = op["method"]
        path = op["path"]
        path_params = op["path_params"]
        request_type = op["request_type_py"]
        response_type = op["response_type_py"]

        sig_bits = [f"{p}: str" for p in path_params]
        sig_bits.append("params: Optional[Dict[str, Any]] = None")
        sig_bits.append(f"body: Optional[{request_type}] = None")
        sig_bits.append("timeout: Optional[int] = None")
        sig_bits.append("max_retries: Optional[int] = None")
        sig_bits.append("backoff_base_seconds: Optional[float] = None")
        sig_bits.append("logger: Optional[Callable[[Dict[str, Any]], None]] = None")
        sig = ", ".join(sig_bits)
        lines.append("")
        lines.append(f"    def {op_id}(self, *, {sig}) -> {response_type}:")
        if path_params:
            lines.append(f"        path = f\"{_to_py_path_template(path)}\"")
            lines.append(
                f"        return self._request('{method}', path, params=params, body=body, timeout=timeout, max_retries=max_retries, backoff_base_seconds=backoff_base_seconds)"
                .replace("backoff_base_seconds=backoff_base_seconds)", "backoff_base_seconds=backoff_base_seconds, logger=logger)")
            )
        else:
            lines.append(
                f"        return self._request('{method}', '{path}', params=params, body=body, timeout=timeout, max_retries=max_retries, backoff_base_seconds=backoff_base_seconds)"
                .replace("backoff_base_seconds=backoff_base_seconds)", "backoff_base_seconds=backoff_base_seconds, logger=logger)")
            )

    for op in ops:
        if op["method"] != "GET":
            continue
        paginator = op.get("paginator")
        if not paginator:
            continue
        op_id = op["operation_id"]
        path_params = op["path_params"]
        item_type = paginator["item_type_py"]

        sig_bits = [f"{p}: str" for p in path_params]
        sig_bits.extend(
            [
                "params: Optional[Dict[str, Any]] = None",
                "page_size: int = 200",
                "max_pages: int = 100",
                "timeout: Optional[int] = None",
                "max_retries: Optional[int] = None",
                "backoff_base_seconds: Optional[float] = None",
                "logger: Optional[Callable[[Dict[str, Any]], None]] = None",
            ]
        )
        sig = ", ".join(sig_bits)
        call_bits = [f"{p}={p}" for p in path_params]
        call_bits.append("params=page_params")
        call_args = ", ".join(call_bits)

        lines.extend(
            [
                "",
                f"    def {op_id}_all(self, *, {sig}) -> List[{item_type}]:",
                f"        items: List[{item_type}] = []",
                "        base_params = dict(params or {})",
                "        offset = int(base_params.get('offset', 0) or 0)",
                "        for _ in range(max_pages):",
                "            page_params = dict(base_params)",
                "            page_params['limit'] = page_size",
                "            page_params['offset'] = offset",
                f"            page = self.{op_id}({call_args}, timeout=timeout, max_retries=max_retries, backoff_base_seconds=backoff_base_seconds, logger=logger)",
                "            data = page.get('data', {}) if isinstance(page, dict) else {}",
                "            page_items = data.get('items', []) if isinstance(data, dict) else []",
                "            if not isinstance(page_items, list):",
                "                break",
                "            items.extend(page_items)",
                "            raw_count = data.get('count', len(page_items)) if isinstance(data, dict) else len(page_items)",
                "            try:",
                "                page_count = int(raw_count)",
                "            except Exception:",
                "                page_count = len(page_items)",
                "            if page_count <= 0 or page_count < page_size:",
                "                break",
                "            offset += page_count",
                "        return items",
            ]
        )

    lines.append("")
    return "\n".join(lines)


def _render_ts_client(ops: List[Dict[str, Any]], schemas: Dict[str, Any]) -> str:
    lines = [
        "// Generated client baseline for Greenlight API. Do not edit by hand.",
        "",
        "export type QueryParams = Record<string, string | number | boolean | null | undefined>;",
        "export type RequestLogEvent = {",
        "  event: 'http_request' | 'http_error' | 'network_error';",
        "  method: string;",
        "  path: string;",
        "  statusCode?: number;",
        "  durationMs: number;",
        "  attempt: number;",
        "  requestId?: string;",
        "  errorCode?: string;",
        "  hasBody: boolean;",
        "  queryKeys: string[];",
        "};",
        "export type RequestLogger = (event: RequestLogEvent) => void | Promise<void>;",
        "export interface RequestOptions { timeoutMs?: number; maxRetries?: number; backoffBaseMs?: number; logger?: RequestLogger }",
        "export class GreenlightApiError extends Error {",
        "  constructor(",
        "    public readonly statusCode: number | undefined,",
        "    public readonly code: string,",
        "    public readonly requestId: string | undefined,",
        "    public readonly details: unknown,",
        "    message: string,",
        "  ) {",
        "    super(message);",
        "    this.name = 'GreenlightApiError';",
        "  }",
        "}",
        "",
        "export type ApiResponse<T = unknown> = {",
        "  ok: boolean;",
        "  data?: T;",
        "  error?: { code?: string; message?: string; details?: unknown };",
        "};",
        "",
    ]
    lines.extend(_render_ts_models(schemas))
    lines.extend(
        [
            "export class GreenlightClient {",
            "  constructor(",
            "    private readonly baseUrl: string,",
            "    private readonly apiKey: string,",
            "    private readonly maxRetries = 3,",
            "    private readonly backoffBaseMs = 250,",
            "    private readonly timeoutMs = 30000,",
            "    private readonly logger?: RequestLogger,",
            "  ) {}",
            "",
            "  private shouldRetryStatus(status: number): boolean {",
            "    return status === 429 || (status >= 500 && status < 600);",
            "  }",
            "",
            "  private async sleepBackoff(attempt: number): Promise<void> {",
            "    const delay = this.backoffBaseMs * (2 ** attempt);",
            "    await new Promise((resolve) => setTimeout(resolve, delay));",
            "  }",
            "",
            "  private async request<T>(method: string, path: string, query?: QueryParams, body?: unknown, requestOptions?: RequestOptions): Promise<T> {",
            "    const url = new URL(`${this.baseUrl.replace(/\\/$/, \"\")}${path}`);",
            "    if (query) {",
            "      for (const [k, v] of Object.entries(query)) {",
            "        if (v !== undefined && v !== null) url.searchParams.set(k, String(v));",
            "      }",
            "    }",
            "    const effectiveRetries = requestOptions?.maxRetries ?? this.maxRetries;",
            "    const effectiveBackoff = requestOptions?.backoffBaseMs ?? this.backoffBaseMs;",
            "    const effectiveTimeout = requestOptions?.timeoutMs ?? this.timeoutMs;",
            "    const logger = requestOptions?.logger ?? this.logger;",
            "    const queryKeys = Object.keys(query ?? {}).sort();",
            "    const hasBody = body !== undefined;",
            "    const attempts = Math.max(effectiveRetries, 0) + 1;",
            "    let lastError: unknown = undefined;",
            "    let lastRequestId: string | undefined = undefined;",
            "    for (let attempt = 0; attempt < attempts; attempt += 1) {",
            "      try {",
            "        const attemptStart = performance.now();",
            "        const controller = new AbortController();",
            "        const timeoutHandle = setTimeout(() => controller.abort(), effectiveTimeout);",
            "        const resp = await fetch(url.toString(), {",
            "          method,",
            "          headers: {",
            "            Authorization: `Bearer ${this.apiKey}`,",
            "            \"Content-Type\": \"application/json\",",
            "          },",
            "          body: body === undefined ? undefined : JSON.stringify(body),",
            "          signal: controller.signal,",
            "        });",
            "        clearTimeout(timeoutHandle);",
            "        if (!resp.ok) {",
            "          const txt = await resp.text();",
            "          let code = 'HTTP_ERROR';",
            "          let message = `HTTP ${resp.status}`;",
            "          let details: unknown = undefined;",
            "          try {",
            "            const parsed = txt ? JSON.parse(txt) : null;",
            "            if (parsed && typeof parsed === 'object') {",
            "              const err = (parsed as any).error;",
            "              if (err && typeof err === 'object') {",
            "                code = String((err as any).code ?? code);",
            "                message = String((err as any).message ?? message);",
            "                details = (err as any).details;",
            "              }",
            "            }",
            "          } catch {",
            "            message = txt || message;",
            "          }",
            "          const apiErr = new GreenlightApiError(",
            "            resp.status,",
            "            code,",
            "            resp.headers.get('x-request-id') ?? undefined,",
            "            details,",
            "            message,",
            "          );",
            "          lastRequestId = apiErr.requestId ?? lastRequestId;",
            "          if (attempt + 1 < attempts && this.shouldRetryStatus(resp.status)) {",
            "            if (logger) {",
            "              await Promise.resolve(logger({ event: 'http_error', method, path, statusCode: resp.status, durationMs: Math.round((performance.now() - attemptStart) * 100) / 100, attempt: attempt + 1, requestId: apiErr.requestId, errorCode: apiErr.code, hasBody, queryKeys }));",
            "            }",
            "            await new Promise((resolve) => setTimeout(resolve, effectiveBackoff * (2 ** attempt)));",
            "            continue;",
            "          }",
            "          if (logger) {",
            "            await Promise.resolve(logger({ event: 'http_error', method, path, statusCode: resp.status, durationMs: Math.round((performance.now() - attemptStart) * 100) / 100, attempt: attempt + 1, requestId: apiErr.requestId, errorCode: apiErr.code, hasBody, queryKeys }));",
            "          }",
            "          throw apiErr;",
            "        }",
            "        const text = await resp.text();",
            "        const successRequestId = resp.headers.get('x-request-id') ?? undefined;",
            "        lastRequestId = successRequestId ?? lastRequestId;",
            "        if (logger) {",
            "          await Promise.resolve(logger({ event: 'http_request', method, path, statusCode: resp.status, durationMs: Math.round((performance.now() - attemptStart) * 100) / 100, attempt: attempt + 1, requestId: successRequestId, hasBody, queryKeys }));",
            "        }",
            "        return (text ? JSON.parse(text) : { ok: false, error: { code: 'EMPTY_RESPONSE', message: 'Empty response body' } }) as T;",
            "      } catch (err) {",
            "        if (err instanceof GreenlightApiError) {",
            "          lastError = err;",
            "          if (attempt + 1 < attempts && err.statusCode !== undefined && this.shouldRetryStatus(err.statusCode)) {",
            "            await new Promise((resolve) => setTimeout(resolve, effectiveBackoff * (2 ** attempt)));",
            "            continue;",
            "          }",
            "          throw err;",
            "        }",
            "        const isAbort = err instanceof DOMException && err.name === 'AbortError';",
            "        const networkErr = new GreenlightApiError(",
            "          undefined,",
            "          isAbort ? 'TIMEOUT' : 'NETWORK_ERROR',",
            "          lastRequestId,",
            "          undefined,",
            "          err instanceof Error ? err.message : String(err),",
            "        );",
            "        lastError = networkErr;",
            "        if (logger) {",
            "          await Promise.resolve(logger({ event: 'network_error', method, path, durationMs: 0, attempt: attempt + 1, requestId: networkErr.requestId, errorCode: networkErr.code, hasBody, queryKeys }));",
            "        }",
            "        if (attempt + 1 < attempts) {",
            "          await new Promise((resolve) => setTimeout(resolve, effectiveBackoff * (2 ** attempt)));",
            "          continue;",
            "        }",
            "        throw networkErr;",
            "      }",
            "    }",
            "    throw (lastError instanceof Error ? lastError : new GreenlightApiError(undefined, 'REQUEST_FAILED', lastRequestId, undefined, 'Request failed'));",
            "  }",
        ]
    )

    for op in ops:
        op_id = op["operation_id"]
        method = op["method"]
        path = op["path"]
        path_params = op["path_params"]
        request_type = op["request_type_ts"]
        response_type = op["response_type_ts"]

        fields = [f"{p}: string;" for p in path_params]
        fields.append("query?: QueryParams;")
        fields.append(f"body?: {request_type};")
        fields.append("requestOptions?: RequestOptions;")
        arg_shape = " ".join(fields)

        lines.append("")
        lines.append(f"  async {op_id}(args: {{ {arg_shape} }}): Promise<{response_type}> {{")
        if path_params:
            lines.append(f"    const path = `{_to_ts_path_template(path)}`;")
            lines.append(f"    return this.request<{response_type}>('{method}', path, args.query, args.body, args.requestOptions);")
        else:
            lines.append(f"    return this.request<{response_type}>('{method}', '{path}', args.query, args.body, args.requestOptions);")
        lines.append("  }")

    for op in ops:
        if op["method"] != "GET":
            continue
        paginator = op.get("paginator")
        if not paginator:
            continue
        op_id = op["operation_id"]
        path_params = op["path_params"]
        item_type = paginator["item_type_ts"]

        fields = [f"{p}: string;" for p in path_params]
        fields.extend(["query?: QueryParams;", "pageSize?: number;", "maxPages?: number;", "requestOptions?: RequestOptions;"])
        arg_shape = " ".join(fields)
        path_call = ", ".join([f"{p}: args.{p}" for p in path_params])
        if path_call:
            path_call += ", "

        lines.extend(
            [
                "",
                f"  async {op_id}_all(args: {{ {arg_shape} }} = {{}}): Promise<{item_type}[]> {{",
                f"    const items: {item_type}[] = [];",
                "    const pageSize = args.pageSize ?? 200;",
                "    const maxPages = args.maxPages ?? 100;",
                "    const baseQuery: QueryParams = { ...(args.query ?? {}) };",
                "    let offset = Number(baseQuery.offset ?? 0);",
                "    for (let i = 0; i < maxPages; i += 1) {",
                "      const query: QueryParams = { ...baseQuery, limit: pageSize, offset };",
                f"      const page = await this.{op_id}({{{path_call}query, requestOptions: args.requestOptions }});",
                "      const pageItems = Array.isArray(page?.data?.items) ? page.data.items : [];",
                f"      items.push(...(pageItems as {item_type}[]));",
                "      const rawCount = page?.data?.count ?? pageItems.length;",
                "      const pageCount = Number.isFinite(Number(rawCount)) ? Number(rawCount) : pageItems.length;",
                "      if (pageCount <= 0 || pageCount < pageSize) break;",
                "      offset += pageCount;",
                "    }",
                "    return items;",
                "  }",
            ]
        )

    lines.extend(["}", ""])
    return "\n".join(lines)


def main() -> None:
    schema = TestClient(app).get("/openapi.json").json()
    schemas = schema.get("components", {}).get("schemas", {})
    ops = _operations(schema)

    PY_OUT.write_text(_render_python_client(ops, schemas), encoding="utf-8")
    TS_OUT.write_text(_render_ts_client(ops, schemas), encoding="utf-8")

    print(f"Generated {len(ops)} operations")
    print(PY_OUT)
    print(TS_OUT)


if __name__ == "__main__":
    main()
