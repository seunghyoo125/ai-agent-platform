from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import ssl
import time
from typing import Any, Dict, Optional
from urllib import error, request

import certifi


class ExecutionServiceError(Exception):
    pass


class ExecutionConfigurationError(ExecutionServiceError):
    pass


class ExecutionRuntimeError(ExecutionServiceError):
    pass


@dataclass
class ExecutionContext:
    mode: str = "simulated"
    timeout_ms: int = 15000
    endpoint: Optional[str] = None
    headers: Optional[Dict[str, str]] = None


class ExecutionService:
    def __init__(self, context: ExecutionContext) -> None:
        self.context = context

    def execute_case(
        self,
        input_text: str,
        expected_output: Optional[str] = None,
        acceptable_sources: Optional[str] = None,
    ) -> Dict[str, Any]:
        started = time.perf_counter()
        base = (expected_output or "").strip()
        if not base:
            base = f"Draft response for: {input_text}"
        sources = (acceptable_sources or "").strip()
        response = base
        if sources:
            response = f"{base} Source: {sources}."
        duration_ms = round((time.perf_counter() - started) * 1000, 2)
        return {
            "actual_response": response,
            "actual_sources": sources or None,
            "trace": {
                "executor_mode": "simulated",
                "duration_ms": duration_ms,
                "request_hash": _sha256(json.dumps({"input": input_text}, ensure_ascii=True)),
                "response_hash": _sha256(response),
            },
        }


class HttpAgentExecutionService(ExecutionService):
    @staticmethod
    def _ssl_context() -> ssl.SSLContext:
        return ssl.create_default_context(cafile=certifi.where())

    def execute_case(
        self,
        input_text: str,
        expected_output: Optional[str] = None,
        acceptable_sources: Optional[str] = None,
    ) -> Dict[str, Any]:
        del expected_output
        del acceptable_sources
        transport = _agent_http_post(
            endpoint=self.context.endpoint,
            input_text=input_text,
            timeout_ms=self.context.timeout_ms,
            headers=self.context.headers,
        )
        text = transport["text"]
        actual_response = ""
        actual_sources: Optional[str] = None
        response_preview = str(transport["response_preview"])

        if str(transport["content_type"]).lower().find("application/json") >= 0:
            try:
                parsed = json.loads(text)
            except Exception as exc:
                raise ExecutionRuntimeError(f"Agent JSON response parse failed: {exc}") from exc
            actual_response, actual_sources = _extract_agent_output(parsed)
            response_preview = json.dumps(parsed, ensure_ascii=True)[:1000]
        else:
            actual_response = text.strip()

        if not actual_response:
            raise ExecutionRuntimeError("Agent response did not include usable output.")

        duration_ms = float(transport["duration_ms"])
        return {
            "actual_response": actual_response,
            "actual_sources": actual_sources,
            "trace": {
                "executor_mode": "agent_http",
                "executor_target": str(transport["endpoint"]),
                "duration_ms": duration_ms,
                "status_code": int(transport["status_code"]),
                "request_hash": str(transport["request_hash"]),
                "response_hash": str(transport["response_hash"]),
                "response_preview": response_preview,
            },
        }


def validate_agent_invoke_contract(
    endpoint: Optional[str],
    sample_input: str,
    timeout_ms: int = 15000,
    headers: Optional[Dict[str, str]] = None,
) -> Dict[str, Any]:
    transport = _agent_http_post(
        endpoint=endpoint,
        input_text=sample_input,
        timeout_ms=timeout_ms,
        headers=headers,
    )
    content_type = str(transport["content_type"]).lower()
    text = str(transport["text"])
    issues: list[str] = []
    response_key_used: Optional[str] = None
    source_key_used: Optional[str] = None
    parsed_payload: Optional[Dict[str, Any]] = None
    extracted_response = ""
    extracted_sources: Optional[str] = None

    if "application/json" in content_type:
        try:
            parsed = json.loads(text)
        except Exception as exc:
            issues.append(f"JSON parse failed: {exc}")
            parsed = None
        if isinstance(parsed, dict):
            parsed_payload = parsed
            extracted_response, extracted_sources, response_key_used, source_key_used = _extract_agent_output_with_keys(parsed)
        elif parsed is not None:
            extracted_response = str(parsed)
    else:
        extracted_response = text.strip()

    if not extracted_response.strip():
        issues.append("Response did not expose a usable output field.")

    if parsed_payload is None and "application/json" in content_type:
        issues.append("Response Content-Type is JSON but payload was not parseable.")

    valid = len(issues) == 0
    return {
        "valid": valid,
        "issues": issues,
        "endpoint": str(transport["endpoint"]),
        "status_code": int(transport["status_code"]),
        "latency_ms": float(transport["duration_ms"]),
        "content_type": str(transport["content_type"]),
        "response_preview": str(transport["response_preview"]),
        "request_hash": str(transport["request_hash"]),
        "response_hash": str(transport["response_hash"]),
        "response_key_used": response_key_used,
        "source_key_used": source_key_used,
        "extracted_response": extracted_response,
        "extracted_sources": extracted_sources,
    }


def _agent_http_post(
    endpoint: Optional[str],
    input_text: str,
    timeout_ms: int,
    headers: Optional[Dict[str, str]],
) -> Dict[str, Any]:
    endpoint_value = (endpoint or "").strip()
    if not endpoint_value:
        raise ExecutionConfigurationError("Agent executor endpoint is required for mode=agent_http.")

    started = time.perf_counter()
    payload = {"input": input_text}
    body_bytes = json.dumps(payload).encode("utf-8")
    req_headers = {"Content-Type": "application/json"}
    if headers:
        req_headers.update(headers)

    req = request.Request(
        url=endpoint_value,
        method="POST",
        headers=req_headers,
        data=body_bytes,
    )
    timeout_seconds = max(1.0, timeout_ms / 1000.0)
    try:
        with request.urlopen(req, timeout=timeout_seconds, context=HttpAgentExecutionService._ssl_context()) as resp:
            status_code = int(resp.status)
            raw = resp.read()
            content_type = str(resp.headers.get("Content-Type", "")).lower()
    except error.HTTPError as exc:
        raw = exc.read().decode("utf-8", errors="replace")
        raise ExecutionRuntimeError(f"Agent HTTP {exc.code}: {raw}") from exc
    except Exception as exc:
        raise ExecutionRuntimeError(f"Agent execution request failed: {exc}") from exc

    text = raw.decode("utf-8", errors="replace")
    duration_ms = round((time.perf_counter() - started) * 1000, 2)
    return {
        "endpoint": endpoint_value,
        "status_code": status_code,
        "content_type": content_type,
        "raw": raw,
        "text": text,
        "duration_ms": duration_ms,
        "request_hash": _sha256(body_bytes),
        "response_hash": _sha256(raw),
        "response_preview": text[:1000],
    }


def _extract_agent_output(payload: Any) -> tuple[str, Optional[str]]:
    if isinstance(payload, str):
        return payload.strip(), None
    if not isinstance(payload, dict):
        return str(payload), None

    response_keys = ("response", "answer", "output", "text", "content", "generated")
    for key in response_keys:
        val = payload.get(key)
        if isinstance(val, str) and val.strip():
            return val.strip(), _extract_sources(payload)

    data = payload.get("data")
    if isinstance(data, dict):
        for key in response_keys:
            val = data.get(key)
            if isinstance(val, str) and val.strip():
                return val.strip(), _extract_sources(payload)

    return json.dumps(payload, ensure_ascii=True), _extract_sources(payload)


def _extract_agent_output_with_keys(payload: Dict[str, Any]) -> tuple[str, Optional[str], Optional[str], Optional[str]]:
    response_keys = ("response", "answer", "output", "text", "content", "generated")
    source_keys = ("sources", "source", "references", "citations")
    for key in response_keys:
        val = payload.get(key)
        if isinstance(val, str) and val.strip():
            src, src_key = _extract_sources_with_key(payload, source_keys)
            return val.strip(), src, key, src_key

    data = payload.get("data")
    if isinstance(data, dict):
        for key in response_keys:
            val = data.get(key)
            if isinstance(val, str) and val.strip():
                src, src_key = _extract_sources_with_key(payload, source_keys)
                return val.strip(), src, f"data.{key}", src_key

    src, src_key = _extract_sources_with_key(payload, source_keys)
    return json.dumps(payload, ensure_ascii=True), src, None, src_key


def _extract_sources(payload: Dict[str, Any]) -> Optional[str]:
    value, _ = _extract_sources_with_key(payload, ("sources", "source", "references", "citations"))
    return value


def _extract_sources_with_key(payload: Dict[str, Any], source_keys: tuple[str, ...]) -> tuple[Optional[str], Optional[str]]:
    for key in source_keys:
        val = payload.get(key)
        if isinstance(val, str) and val.strip():
            return val.strip(), key
        if isinstance(val, list):
            cleaned = [str(x).strip() for x in val if str(x).strip()]
            if cleaned:
                return ", ".join(cleaned), key
    data = payload.get("data")
    if isinstance(data, dict):
        for key in source_keys:
            val = data.get(key)
            if isinstance(val, str) and val.strip():
                return val.strip(), f"data.{key}"
            if isinstance(val, list):
                cleaned = [str(x).strip() for x in val if str(x).strip()]
                if cleaned:
                    return ", ".join(cleaned), f"data.{key}"
    return None, None


def _sha256(raw: Any) -> str:
    if isinstance(raw, str):
        b = raw.encode("utf-8")
    elif isinstance(raw, bytes):
        b = raw
    else:
        b = json.dumps(raw, ensure_ascii=True).encode("utf-8")
    return hashlib.sha256(b).hexdigest()


def get_execution_service(
    mode: str,
    agent_endpoint: Optional[str],
    timeout_ms: int = 15000,
    headers: Optional[Dict[str, str]] = None,
) -> ExecutionService:
    normalized = (mode or "simulated").strip()
    if normalized == "auto":
        normalized = "agent_http" if agent_endpoint else "simulated"
    context = ExecutionContext(mode=normalized, endpoint=agent_endpoint, timeout_ms=timeout_ms, headers=headers or {})
    if normalized == "simulated":
        return ExecutionService(context=context)
    if normalized == "agent_http":
        return HttpAgentExecutionService(context=context)
    raise ExecutionConfigurationError(f"Unsupported executor mode: {normalized}")
