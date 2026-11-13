# CTF Reverse - 用 msynth 化简 MBA

<a id="mba-simplification-with-msynth"></a>
## 用 msynth 化简 MBA

混合布尔-算术（MBA, Mixed Boolean-Arithmetic）混淆会把简单运算（例如 `x + y`）改写成位运算与算术运算交织的形式。反编译输出中典型的 MBA 形态：

```c
// MBA 混淆的加法 —— 认出 (x ^ y) + 2 * (x & y) 这个模式
out = (x ^ y) + 2 * (x & y);   // == x + y
```

**关键要点：** `(x ^ y) + 2*(x & y) == x + y` —— XOR 承载不带进位的求和位，AND 移位项恢复进位。识别启发式：反编译输出在同一批变量上把 `^`、`&`、`|` 与 `+`、`*` 以及小常数（尤其 `* 2`）混用，未经证实之前都应视为 MBA。

<a id="install"></a>
### 安装

```bash
uv pip install "msynth @ git+https://github.com/mrphrazer/msynth.git" z3-solver
uv pip install "miasm @ git+https://github.com/cea-sec/miasm.git@1dc5fa9"
```

> 注意：msynth 不在 PyPI 上（`uv pip install msynth` 会报 "not found in the package registry"）—— 从 git URL 安装。miasm 锁定到 commit `1dc5fa9`：PyPI 上的 miasm 发行版会 import 早已废弃的 `imp` 模块，在 Python 3.12+ 上直接崩。冒烟测试：`python -c "from msynth import Simplifier, Synthesizer"`。

<a id="simplifier-path-oracle-lookup"></a>
### Simplifier 路径（查表）

`Simplifier` 在预计算的 I/O 等价类 oracle 中查找合并后的子表达式。oracle 不是开箱即用的：msynth 仓库的 `database/` 目录里有一张 `3_variables_constants_7_nodes.txt.zip` 表达式表（1,293,020 种组合），你可以用它自行构建 oracle（10 分钟以上），或者直接下载 msynth README 中链接的预计算 `oracle.pickle`：

```bash
git clone https://github.com/mrphrazer/msynth.git
unzip -d msynth/database -q msynth/database/3_variables_constants_7_nodes.txt.zip
python msynth/scripts/gen_oracle.py msynth/database/3_variables_constants_7_nodes.txt oracle.pickle
```

```python
from pathlib import Path
from msynth import Simplifier, parse_infix_expr

simp = Simplifier(oracle_path=Path("oracle.pickle"))
out = simp.simplify(parse_infix_expr("(x ^ y) + 2*(x & y)"))
print(out)  # x + y
```

当 `oracle_path=None` 时，oracle 分支永远失配，只走 SimBA 重写 —— 对轻度 MBA 仍有用，但面对困难输入时主要靠 oracle 承担工作量。

<a id="synthesizer-path-from-scratch-search"></a>
### Synthesizer 路径（从零搜索）

没有 oracle 时，`Synthesizer(use_smir=True).simplify` 通过 `iterated_local_search` 从零搜索候选重写。速度慢（每个表达式几秒到几分钟）且带有随机性 —— 在之前的冒烟测试中，一个困难 MBA 跑了 61 秒仍无变化，所以要预留时间并重试：

```python
from msynth import Synthesizer, parse_infix_expr

orig = parse_infix_expr("(x ^ y) + 2*(x & y)")
out = Synthesizer(use_smir=True).simplify(orig, num_samples=10, timeout=60)
print(out)  # x + y（此输入实测 0.9 s）
```

<a id="equivalence-check-mandatory"></a>
### 等价性校验（必做）

永远不要盲目相信化简器 —— 合成过程有随机性，一个错误的"化简"会静默地毁掉解题。在 N 个随机 64 位输入上分别求两侧值、断言相等，任何不匹配都视为合成失败（延长超时重试，或退回手工分析）：

```python
import random
import z3
from miasm.ir.translators.z3_ir import TranslatorZ3

def check_equivalent(a, b, n=2000, seed=0xC7F):
    """在 64 位输入上做随机差分测试。当且仅当 N 次全部一致时返回 True。"""
    rng = random.Random(seed)
    names = sorted({str(x) for x in a.get_r()} | {str(x) for x in b.get_r()})
    t = TranslatorZ3()
    za, zb = t.from_expr(a), t.from_expr(b)
    zvars = {v: z3.BitVec(v, 64) for v in names}
    for _ in range(n):
        sub = [(zvars[v], z3.BitVecVal(rng.getrandbits(64), 64)) for v in names]
        va = z3.simplify(z3.substitute(za, *sub)).as_long() & (1 << 64) - 1
        vb = z3.simplify(z3.substitute(zb, *sub)).as_long() & (1 << 64) - 1
        if va != vb:
            return False
    return True

assert check_equivalent(orig, out, n=2000), "synthesis failure: outputs differ"
```

<a id="miasm-integration"></a>
### Miasm 集成

msynth 的表达式就是 miasm 的 `Expr` 对象，因此结果可以直接接入基于 miasm 的工具，例如 `miasm/expression/simplifications.py`（`ExpressionSimplifier` / `expr_simp`）做进一步归约或 SMT 推理。

<a id="ecosystem-map"></a>
### 生态一览

- msynth —— <https://github.com/mrphrazer/msynth>
- GAMBA："Automated MBA Deobfuscation"（<https://arxiv.org/abs/2209.06335>）及其后续论文（<https://arxiv.org/abs/2305.06763>）
- SiMBA（msynth 默认流水线中的化简器）与 mba-blast/Arybo —— 只有当手头目标可以引用它们时才去查阅
