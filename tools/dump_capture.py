"""Dump captured GSA traffic from a mitmproxy flow file."""

import sys
import plistlib
from mitmproxy import io
from mitmproxy.exceptions import FlowReadException

CAPTURE = r"E:\tools\ipasign\capture\sideloadly.mitm"


def short(value: str, limit: int = 120) -> str:
    value = str(value)
    return value if len(value) <= limit else value[:limit] + f"...<{len(value)}>"


def main() -> int:
    with open(CAPTURE, "rb") as handle:
        reader = io.FlowReader(handle)
        flows = []
        try:
            for flow in reader.stream():
                flows.append(flow)
        except FlowReadException as exc:
            print("flow read error:", exc)

    print(f"flows: {len(flows)}")
    for flow in flows:
        request = getattr(flow, "request", None)
        if request is None:
            continue
        host = request.pretty_host
        if "apple.com" not in host:
            continue
        print("=" * 70)
        print(f"{request.method} https://{host}{request.path}")
        for key, value in request.headers.items():
            if key.lower() in ("x-apple-i-md", "x-apple-i-md-m", "x-apple-i-md-lu"):
                print(f"  {key}: {short(value, 40)}")
            else:
                print(f"  {key}: {short(value)}")
        body = request.get_content() or b""
        print(f"  body: {len(body)} bytes")
        if body:
            try:
                payload = plistlib.loads(body)
                print("  plist:", _summarize(payload))
            except Exception:
                print("  raw:", short(body[:300]))
        response = getattr(flow, "response", None)
        if response is not None:
            print(f"  <- {response.status_code} {short(response.reason)}")
            rbody = response.get_content() or b""
            print(f"  response body: {len(rbody)} bytes")
            if rbody:
                try:
                    payload = plistlib.loads(rbody)
                    print("  response plist:", _summarize(payload))
                except Exception:
                    print("  response raw:", short(rbody[:300]))
    return 0


def _summarize(value, depth=0):
    if isinstance(value, dict):
        return {
            key: _summarize(item, depth + 1)
            for key, item in value.items()
            if key not in ("cpd",)
        } | ({"cpd": "<dict>"} if "cpd" in value else {})
    if isinstance(value, bytes):
        return f"<{len(value)} bytes>"
    if isinstance(value, str) and len(value) > 60:
        return value[:60] + f"...<{len(value)}>"
    if isinstance(value, list):
        return [_summarize(item, depth + 1) for item in value]
    return value


if __name__ == "__main__":
    raise SystemExit(main())
