import concurrent.futures
import contextlib
import json
import os
import random
import re
import string
import sys
import time
import urllib.parse
import urllib.request
from dataclasses import dataclass
from http.cookiejar import CookieJar
from html.parser import HTMLParser
from typing import Dict, List, Optional, Tuple, Any

HAS_SOCKS = False
with contextlib.suppress(Exception):
    import socks, socket  # type: ignore
    HAS_SOCKS = True

def rand_string(min_len: int, max_len: int) -> str:
    n = random.randint(min_len, max_len)
    alphabet = string.ascii_letters + string.digits
    return "".join(random.choice(alphabet) for _ in range(n))

ZERO_WIDTH = ["\u200b", "\u200c", "\u200d", "\ufeff"]
COMBINING_MARKS = [chr(c) for c in range(0x0300, 0x036F + 1)]
CJK = [chr(c) for c in range(0x4E00, 0x9FFF, 13)]
SYMBOLS = list("§¶†‡•‣※★☆☯☢☠♠♥♦♣♻✓✔✕✦✧⚑⚠☂☃♬")
MIXED = list("абвгджзилопртуфхцчшщŷžȳėūėįšøåéàüñ")

def bug_text(level: str = "light", base_len: int = 24) -> str:
    if level not in {"light", "medium", "heavy"}:
        level = "light"
    n = base_len if level == "light" else base_len * (2 if level == "medium" else 3)
    parts = []
    for _ in range(n):
        bucket = random.choices(
            population=["ascii", "zero_width", "comb", "cjk", "sym", "mixed"],
            weights={"light":[10,1,1,2,1,2],"medium":[6,2,2,4,2,4],"heavy":[3,3,3,6,3,6]}[level],
            k=1
        )[0]
        if bucket == "ascii":
            ch = random.choice(string.ascii_letters + string.digits + " _-.,;:/")
        elif bucket == "zero_width":
            ch = random.choice(ZERO_WIDTH)
        elif bucket == "comb":
            ch = random.choice(COMBINING_MARKS)
        elif bucket == "cjk":
            ch = random.choice(CJK)
        elif bucket == "sym":
            ch = random.choice(SYMBOLS)
        else:
            ch = random.choice(MIXED)
        parts.append(ch)
    glitched = []
    for p in parts:
        glitched.append(p)
        if random.random() < (0.15 if level=="light" else 0.35 if level=="medium" else 0.55):
            for _ in range(random.randint(1, 3)):
                glitched.append(random.choice(COMBINING_MARKS))
    return "".join(glitched)

TEMPLATE_VAR_RE = re.compile(r"\$\{([a-zA-Z_]+)(?::([^}]+))?\}")

def expand_template(s: str) -> str:
    def repl(m: re.Match) -> str:
        name = m.group(1)
        arg = m.group(2) or ""
        if name == "random_string":
            try:
                a, b = [int(x) for x in arg.split(",")]
            except Exception:
                a, b = 8, 12
            return rand_string(a, b)
        elif name == "bug_text":
            level = "light"
            base_len = 24
            if arg:
                if ";" in arg:
                    level, ln = arg.split(";", 1)
                    with contextlib.suppress(ValueError):
                        base_len = int(ln)
                else:
                    level = arg
            return bug_text(level=level, base_len=base_len)
        else:
            return m.group(0)
    return TEMPLATE_VAR_RE.sub(repl, s)


class SimpleFormParser(HTMLParser):
    def __init__(self, token_hints: List[str]):
        super().__init__()
        self.in_form = False
        self.form_action = None
        self.form_method = None
        self.hidden_inputs: Dict[str, str] = {}
        self.token_hints = {h.lower() for h in token_hints}

    def handle_starttag(self, tag, attrs):
        attrs_dict = dict(attrs)
        if tag.lower() == "form":
            self.in_form = True
            self.form_action = attrs_dict.get("action")
            self.form_method = (attrs_dict.get("method") or "GET").upper()
        if tag.lower() == "input" and self.in_form:
            typ = (attrs_dict.get("type") or "text").lower()
            name = attrs_dict.get("name")
            value = attrs_dict.get("value", "")
            if typ == "hidden" and name:
                self.hidden_inputs[name] = value
        if tag.lower() == "meta":
            name = (attrs_dict.get("name") or "").lower()
            content = attrs_dict.get("content")
            if content and any(h in name for h in self.token_hints):
                self.hidden_inputs[name] = content

    def handle_endtag(self, tag):
        if tag.lower() == "form":
            self.in_form = False


@dataclass
class HttpContext:
    opener: urllib.request.OpenerDirector
    cookiejar: CookieJar

def _apply_headers(opener: urllib.request.OpenerDirector, user_agent: Optional[str], headers: Dict[str, str]):
    default_headers = {
        "User-Agent": user_agent or f"Python-urllib/{urllib.request.__version__}",
        **headers
    }
    opener.addheaders = list(default_headers.items())

def _build_socks_opener(socks_conf: Dict[str, Any]) -> Optional[urllib.request.OpenerDirector]:
    if not HAS_SOCKS:
        return None
    stype = str(socks_conf.get("type", "")).lower()
    host = socks_conf.get("host")
    port = int(socks_conf.get("port", 0))
    username = socks_conf.get("username") or None
    password = socks_conf.get("password") or None
    if not host or not port:
        return None
    type_map = {"socks4": socks.SOCKS4, "socks5": socks.SOCKS5, "socks5h": socks.SOCKS5}
    if stype not in type_map:
        return None

    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(CookieJar()))
    opener._socks_cfg = (type_map[stype], host, port, username, password)
    return opener

def open_with_socks(opener: urllib.request.OpenerDirector, request: urllib.request.Request, timeout: int):
    orig_socket = None
    try:
        stype, host, port, user, pwd = opener._socks_cfg
        socks.set_default_proxy(stype, host, port, username=user, password=pwd)
        orig_socket = socket.socket
        socket.socket = socks.socksocket  # type: ignore
        return opener.open(request, timeout=timeout)
    finally:
        if orig_socket is not None:
            socket.socket = orig_socket  # restore

def build_opener(proxy: Optional[Dict[str, Any]], user_agent: Optional[str], headers: Dict[str, str]) -> HttpContext:
    cj = CookieJar()
    opener: Optional[urllib.request.OpenerDirector] = None
    warn_msg: Optional[str] = None

    if proxy:
        ptype = str(proxy.get("type", "")).lower()
        if ptype in ("socks4", "socks5", "socks5h"):
            if HAS_SOCKS:
                opener = _build_socks_opener(proxy)
                if opener is None:
                    warn_msg = "SOCKS プロキシ設定が不完全のためスキップします。"
            else:
                warn_msg = "PySocks 未導入のため SOCKS プロキシをスキップします。HTTP/HTTPS プロキシまたは直接続を使用します。"
        else:
            handler = urllib.request.ProxyHandler({
                k: v for k, v in proxy.items() if k in ("http", "https")
            })
            opener = urllib.request.build_opener(handler, urllib.request.HTTPCookieProcessor(cj))

    if opener is None:
        opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))

    _apply_headers(opener, user_agent, headers)

    if warn_msg:
        try:
            print(warn_msg, file=sys.stderr)
        except Exception:
            pass

    return HttpContext(opener=opener, cookiejar=cj)

def http_get(ctx: HttpContext, url: str, timeout: int) -> Tuple[int, bytes, Dict[str, str]]:
    req = urllib.request.Request(url, method="GET")
    if hasattr(ctx.opener, "_socks_cfg"):
        with open_with_socks(ctx.opener, req, timeout) as resp:  # type: ignore
            return resp.getcode(), resp.read(), dict(resp.headers.items())
    with ctx.opener.open(req, timeout=timeout) as resp:
        return resp.getcode(), resp.read(), dict(resp.headers.items())

def http_post_form(ctx: HttpContext, url: str, form: Dict[str, str], timeout: int) -> Tuple[int, bytes, Dict[str, str]]:
    data = urllib.parse.urlencode(form).encode("utf-8")
    req = urllib.request.Request(url, data=data, method="POST")
    req.add_header("Content-Type", "application/x-www-form-urlencoded")
    if hasattr(ctx.opener, "_socks_cfg"):
        with open_with_socks(ctx.opener, req, timeout) as resp:  # type: ignore
            return resp.getcode(), resp.read(), dict(resp.headers.items())
    with ctx.opener.open(req, timeout=timeout) as resp:
        return resp.getcode(), resp.read(), dict(resp.headers.items())

def http_post_json(ctx: HttpContext, url: str, obj: Dict[str, Any], timeout: int) -> Tuple[int, bytes, Dict[str, str]]:
    data = json.dumps(obj, ensure_ascii=False).encode("utf-8")
    req = urllib.request.Request(url, data=data, method="POST")
    req.add_header("Content-Type", "application/json; charset=utf-8")
    if hasattr(ctx.opener, "_socks_cfg"):
        with open_with_socks(ctx.opener, req, timeout) as resp:  # type: ignore
            return resp.getcode(), resp.read(), dict(resp.headers.items())
    with ctx.opener.open(req, timeout=timeout) as resp:
        return resp.getcode(), resp.read(), dict(resp.headers.items())


@dataclass
class Config:
    form_page_url: str
    api_post_url: Optional[str]
    submit_mode: str
    threads: int
    total_submissions: int
    min_delay_ms: int
    max_delay_ms: int
    timeout_sec: int
    retries: int
    retry_backoff_base_sec: float
    respect_robots_txt: bool
    proxies: List[Dict[str, Any]]
    user_agents: List[str]
    form: Dict[str, str]
    json_mapping: Dict[str, str]
    csrf_enabled: bool
    csrf_token_hints: List[str]
    extra_hidden_fields: List[str]
    headers: Dict[str, str]

    @staticmethod
    def from_dict(d: Dict) -> "Config":
        csrf = d.get("csrf", {})
        return Config(
            form_page_url=d["form_page_url"],
            api_post_url=d.get("api_post_url"),
            submit_mode=(d.get("submit_mode") or "form").lower(),
            threads=int(d.get("threads", 4)),
            total_submissions=int(d.get("total_submissions", 10)),
            min_delay_ms=int(d.get("min_delay_ms", 100)),
            max_delay_ms=int(d.get("max_delay_ms", 500)),
            timeout_sec=int(d.get("timeout_sec", 20)),
            retries=int(d.get("retries", 2)),
            retry_backoff_base_sec=float(d.get("retry_backoff_base_sec", 0.75)),
            respect_robots_txt=bool(d.get("respect_robots_txt", False)),
            proxies=list(d.get("proxies") or []),
            user_agents=list(d.get("user_agents") or []),
            form=dict(d.get("form") or {}),
            json_mapping=dict(d.get("json_mapping") or {}),
            csrf_enabled=bool(csrf.get("enabled", False)),
            csrf_token_hints=list(csrf.get("token_names_hint") or ["csrf", "_csrf", "csrf_token"]),
            extra_hidden_fields=list(csrf.get("extra_hidden_fields") or []),
            headers=dict(d.get("headers") or {}),
        )

def maybe_sleep_jitter(cfg: Config):
    if cfg.max_delay_ms > 0:
        ms = random.randint(cfg.min_delay_ms, cfg.max_delay_ms)
        time.sleep(ms / 1000.0)

def fetch_form_and_action(cfg: Config, ctx: HttpContext) -> Tuple[str, Dict[str, str], str]:
    code, body, headers = http_get(ctx, cfg.form_page_url, cfg.timeout_sec)
    if code != 200:
        raise RuntimeError(f"GET form page failed: HTTP {code}")
    charset = "utf-8"
    ctype = headers.get("Content-Type") or ""
    if "charset=" in ctype:
        charset = ctype.split("charset=")[-1].split(";")[0].strip()
    text = body.decode(charset, errors="replace")
    parser = SimpleFormParser(token_hints=cfg.csrf_token_hints)
    parser.feed(text)
    action = parser.form_action or cfg.form_page_url
    method = (parser.form_method or "POST").upper()
    hidden = parser.hidden_inputs
    return urllib.parse.urljoin(cfg.form_page_url, action), hidden, method

def build_form_payload(cfg: Config, base_hidden: Dict[str, str]) -> Dict[str, str]:
    payload = {}
    for k, v in cfg.form.items():
        payload[k] = expand_template(v)
    if cfg.csrf_enabled:
        payload.update(base_hidden)
    return {k: ("" if v is None else v) for k, v in payload.items()}

def build_json_payload(cfg: Config) -> Dict[str, Any]:
    expanded = {k: expand_template(v) for k, v in cfg.form.items()}
    if not cfg.json_mapping:
        return expanded
    obj = {}
    for src_key, dst_key in cfg.json_mapping.items():
        obj[dst_key] = expanded.get(src_key, "")
    return obj

def is_transient(http_code: int) -> bool:
    return http_code >= 500 or http_code in (408, 429)

def submit_once(cfg: Config, submission_idx: int) -> Tuple[bool, str]:
    proxy = random.choice(cfg.proxies) if cfg.proxies else None
    ua = random.choice(cfg.user_agents) if cfg.user_agents else None
    ctx = build_opener(proxy, ua, cfg.headers)

    backoff = cfg.retry_backoff_base_sec
    last_err = ""
    for attempt in range(cfg.retries + 1):
        try:
            if cfg.submit_mode == "json":
                if not cfg.api_post_url:
                    raise RuntimeError("api_post_url が設定されていません。")
                payload = build_json_payload(cfg)
                code, body, _ = http_post_json(ctx, cfg.api_post_url, payload, cfg.timeout_sec)
                snippet = body[:200].decode("utf-8", errors="replace")
                if 200 <= code < 400:
                    return True, f"#{submission_idx} HTTP {code} OK | UA={ua or 'default'} | Proxy={'on' if proxy else 'off'} | Resp: {snippet[:120].replace(chr(10),' ')}"
                last_err = f"HTTP {code} | Resp: {snippet}"
                if not is_transient(code):
                    break
            else:
                action_url, hidden, method = fetch_form_and_action(cfg, ctx)
                payload = build_form_payload(cfg, hidden)
                if method != "POST":
                    url = action_url + ("&" if "?" in action_url else "?") + urllib.parse.urlencode(payload)
                    code, body, _ = http_get(ctx, url, cfg.timeout_sec)
                else:
                    code, body, _ = http_post_form(ctx, action_url, payload, cfg.timeout_sec)
                snippet = body[:200].decode("utf-8", errors="replace")
                if 200 <= code < 400:
                    return True, f"#{submission_idx} HTTP {code} OK | UA={ua or 'default'} | Proxy={'on' if proxy else 'off'} | Resp: {snippet[:120].replace(chr(10),' ')}"
                last_err = f"HTTP {code} | Resp: {snippet}"
                if not is_transient(code):
                    break
        except Exception as e:
            last_err = f"{type(e).__name__}: {e}"
        if attempt < cfg.retries:
            time.sleep(backoff * (1.5 + random.random()))
            backoff *= 2.0
    return False, f"#{submission_idx} FAILED after retries | {last_err} | UA={ua or 'default'} | Proxy={'on' if proxy else 'off'}"

def load_config(path: str) -> Config:
    with open(path, "r", encoding="utf-8") as f:
        raw = json.load(f)
    return Config.from_dict(raw)

def main():
    cfg_path = os.environ.get("SCRAPER_CONFIG", "config.json")
    cfg = load_config(cfg_path)

    total = cfg.total_submissions
    print(f"Start submissions: total={total}, threads={cfg.threads}, mode={cfg.submit_mode}")

    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=cfg.threads) as exe:
        futs = []
        for i in range(1, total + 1):
            fut = exe.submit(submit_once, cfg, i)
            futs.append(fut)
            maybe_sleep_jitter(cfg)

        for fut in concurrent.futures.as_completed(futs):
            ok, msg = fut.result()
            results.append((ok, msg))
            print(("OK: " if ok else "ERR:"), msg)

    ok_count = sum(1 for ok, _ in results if ok)
    print(f"Done. Success={ok_count}/{total}")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("Interrupted by user.", file=sys.stderr)
        sys.exit(1)