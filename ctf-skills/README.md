# ctf-skills

[Agent Skills](https://agentskills.io) for solving CTF challenges — web exploitation, binary pwn, and reverse engineering. Works with any tool that supports the Agent Skills spec, including [Claude Code](https://docs.anthropic.com/en/docs/claude-code).

## Installation

```bash
npx skills add ljagiello/ctf-skills
```

## Environment Setup

Two setup strategies depending on your workflow:

### Pre-install (recommended before competitions)

Use the central installer entrypoint:

```bash
bash scripts/install_ctf_tools.sh all
```

Run a narrower mode when you only want one tool group:

```bash
bash scripts/install_ctf_tools.sh python
bash scripts/install_ctf_tools.sh pat
bash scripts/install_ctf_tools.sh apt
bash scripts/install_ctf_tools.sh brew
bash scripts/install_ctf_tools.sh gems
bash scripts/install_ctf_tools.sh go
bash scripts/install_ctf_tools.sh manual
```

Preview what would be installed (skips already-present packages):

```bash
bash scripts/install_ctf_tools.sh --dry-run all
```

Verify what's already installed:

```bash
bash scripts/install_ctf_tools.sh --verify
```

Use `--force` to reinstall everything regardless of what's already present. Install logs are saved to `~/.ctf-tools/`.

The full package lists now live in [scripts/install_ctf_tools.sh](scripts/install_ctf_tools.sh).

> [!TIP]
> The `pat` mode shallow-clones [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings) into `~/.ctf-tools/PayloadsAllTheThings` and links it at `ctf-web/payloads/PayloadsAllTheThings`. Bulk payloads stay out of git; technique files reference `ctf-web/pat-reference.md` with a few exemplar payloads inline.

### On-demand (during challenges)

Each skill's `SKILL.md` has a **Prerequisites** section listing only the tools needed for that category. Install as you go when the agent encounters a missing tool.

## Skills

| Skill | Files | Description |
|-------|-------|-------------|
| **ctf-web** | 23 | SQLi (blind boolean/time/error generators, second-order, WAF bypasses, EXIF metadata injection, keyword fragmentation bypass, MySQL column truncation, DNS record injection, ORDER BY CASE WHERE bypass, QR code input injection, double-keyword filter bypass), Burp Intruder parity via `python-requests.md` (sync, 30-worker `ThreadPoolExecutor`, 100-concurrency `httpx` async, generator streaming feeds, `async_fuzz.py` CLI fuzzer), PayloadsAllTheThings on-demand index (`pat-reference.md`), XSS (AngularJS sandbox escapes, DOM clobbering, CSP bypasses), SSTI (Jinja2, Twig, Go template FuncMap), SSRF (DNS rebinding, cloud metadata), XXE, file upload polyglots, deserialization (Java ysoserial, Python pickle, PHP), JWT (key confusion, dynamic length RSA parameters), OAuth/OIDC, prototype pollution |
| **ctf-pwn** | 65 | Buffer overflow, ROP chains, ret2csu, ret2vdso, vsyscall ROP PIE bypass, bad char XOR bypass, 5 runnable `pwntools==4.15.0` template scripts in `ctf-pwn/scripts/` with `yield` payload generators (ret2libc, SROP, shellcraft asm, format string write-size suites, seccomp ORW), heap exploitation (unlink, House of Force, largebin attack guide, glibc 2.39 tcache key protection + calloc behavior, House of Apple 2 + setcontext SUID variant, House of Tangerine/Einherjar), kernel exploitation (io_uring `CVE-2024-0582`, CET Shadow Stack signal-frame bypass, KASLR, SMEP/SMAP, ret2usr, modprobe_path), format string, SROP with UTF-8 constraints, Linux userland attack playbook + static-signals reference, 43 pwnable.tw writeups (`ctf-pwn/pwnable-tw/`) |
| **ctf-reverse** | 22 | Binary analysis, custom VMs (+ VM bytecode lifting to LLVM IR), WASM, RISC-V, Rust serde, Python bytecode, Unicorn CPU emulation guide (`unicorn-emulation.md`: hooks, mixed-mode 64→32 `retf` with XMM state preservation, MMIO peripherals, Keystone trace inversion), Go (GoReSym), Android APK/DEX/JNI, anti-debug, anti-VM, control flow flattening deobfuscation, radare2 scripting with r2ghidra decompilation, ESIL single-function emulation, and batch-mode byte patching (`radare2-r2pipe.md`), r2frida live-process instrumentation, MBA simplification with msynth, MCP server integration for agent-driven RE (`tools-mcp.md`) |

## Usage

Skills are loaded automatically based on context.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup and contribution guidelines.

## Sponsors

ctf-skills is maintained in my spare time. If it saves your team hours during a competition or a
security assessment, you can [sponsor the project on GitHub](https://github.com/sponsors/ljagiello).

- **$5/month** keeps the lights on and lists you in the thanks below.
- **$25/month** adds your name and a link below.
- **$100/month** puts your logo below.
- **$1,500/month: featured sponsor.** A dedicated section near the top of this README with your
  name, logo, a short description and a link, labelled "Sponsored". You draft the text, I approve
  it. Three-month minimum, paid in advance; month to month or quarterly after that. Bank transfer
  or GitHub Sponsors, invoice on request.

Because ctf-skills serves a security-focused audience, I review every sponsor before accepting:
expect questions about how your product handles access, credentials and data retention. API
credits or discount codes for users are welcome in addition to a sponsorship, not instead of one.

No sponsor yet. Be the first.

## License

MIT

Created by [Lukasz Jagiello](https://lukasz.jagiello.org). Write-up: [lukasz.jagiello.org/projects/ctf-skills](https://lukasz.jagiello.org/projects/ctf-skills).
