# -*- coding: utf-8
"""OpenAI-compatible chat client (funcloud / qwen3-max). Stdlib only."""
from __future__ import annotations

import json
import ssl
import time
import urllib.error
import urllib.request
from typing import Any, Dict, List, Optional

from minidrifter.reasoning.config import load_llm_config


class LLMClientError(RuntimeError):
    pass


def _messages(system: str, user: str) -> List[Dict[str, str]]:
    return [
        {'role': 'system', 'content': system},
        {'role': 'user', 'content': user},
    ]


class LLMClient:
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or load_llm_config()
        if not self.config.get('api_key'):
            raise LLMClientError(
                'Missing API key. Set MiniDrifter_LLM_API_KEY in .env or environment.'
            )

    def chat_json(self, system: str, user: str, *, json_mode: bool = True) -> str:
        """Convenience: system + user string → chat."""
        return self.chat(_messages(system, user), json_mode=json_mode)

    def chat(self, messages: List[Dict[str, str]], *, json_mode: bool = True) -> str:
        max_retries = int(self.config.get('max_retries', 3))
        delay = float(self.config.get('retry_delay_seconds', 2.0))
        last_err: Optional[Exception] = None

        for attempt in range(max_retries):
            try:
                return self._chat_once(messages, json_mode=json_mode)
            except LLMClientError as e:
                last_err = e
                msg = str(e).lower()
                retryable = any(k in msg for k in (
                    'network error', 'ssl', 'eof', 'timed out', 'timeout',
                    'connection reset', '502', '503', '504',
                ))
                if not retryable or attempt >= max_retries - 1:
                    raise
                time.sleep(delay * (attempt + 1))

        raise LLMClientError(str(last_err or 'LLM call failed'))

    def _chat_once(self, messages: List[Dict[str, str]], *, json_mode: bool = True) -> str:
        url = self.config['chat_completions_url']
        body: Dict[str, Any] = {
            'model': self.config.get('model', 'qwen3-max'),
            'messages': messages,
            'temperature': float(self.config.get('temperature', 0.2)),
            'max_tokens': int(self.config.get('max_tokens', 4096)),
        }
        if json_mode:
            body['response_format'] = {'type': 'json_object'}

        data = json.dumps(body).encode('utf-8')
        req = urllib.request.Request(
            url,
            data=data,
            headers={
                'Content-Type': 'application/json',
                'Authorization': f"Bearer {self.config['api_key']}",
            },
            method='POST',
        )
        timeout = int(self.config.get('timeout_seconds', 120))
        ctx = ssl.create_default_context()
        try:
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
                raw = json.loads(resp.read().decode('utf-8'))
        except urllib.error.HTTPError as e:
            detail = e.read().decode('utf-8', errors='replace')
            raise LLMClientError(f'HTTP {e.code}: {detail[:500]}') from e
        except (urllib.error.URLError, ssl.SSLError, TimeoutError, OSError) as e:
            fallback = self._try_fallback(messages, json_mode, timeout, ctx)
            if fallback is not None:
                return fallback
            raise LLMClientError(f'Network error: {e}') from e

        return self._extract_content(raw)

    def _try_fallback(
        self,
        messages: List[Dict[str, str]],
        json_mode: bool,
        timeout: int,
        ctx: ssl.SSLContext,
    ) -> Optional[str]:
        fb = (self.config.get('fallback_base_url') or '').rstrip('/')
        path = self.config.get('chat_completions_path') or '/chat/completions'
        if not fb:
            return None
        url = f"{fb}{path}"
        body: Dict[str, Any] = {
            'model': self.config.get('model', 'qwen3-max'),
            'messages': messages,
            'temperature': float(self.config.get('temperature', 0.2)),
            'max_tokens': int(self.config.get('max_tokens', 4096)),
        }
        if json_mode:
            body['response_format'] = {'type': 'json_object'}
        data = json.dumps(body).encode('utf-8')
        req = urllib.request.Request(
            url,
            data=data,
            headers={
                'Content-Type': 'application/json',
                'Authorization': f"Bearer {self.config['api_key']}",
            },
            method='POST',
        )
        try:
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
                raw = json.loads(resp.read().decode('utf-8'))
            return self._extract_content(raw)
        except Exception:
            return None

    @staticmethod
    def _extract_content(raw: Dict[str, Any]) -> str:
        choices = raw.get('choices') or []
        if not choices:
            raise LLMClientError(f'Empty choices in response: {raw}')
        message = choices[0].get('message') or {}
        content = message.get('content')
        if not content:
            raise LLMClientError(f'Empty message content: {raw}')
        return content
