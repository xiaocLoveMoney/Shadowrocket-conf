"""Shadowrocket 配置校验：语法、策略引用、防 DNS / WebRTC 泄漏约束、远程规则可达性.

用法:
    python3 scripts/check_conf.py [conf 路径] [--online]

退出码 0 表示全部通过, 1 表示存在错误.
"""

from __future__ import annotations

import argparse
import logging
import re
import sys
import urllib.error
import urllib.request
from pathlib import Path

logger = logging.getLogger("check_conf")

DEFAULT_CONF = Path(__file__).resolve().parent.parent / "shadowrocket.conf"

BUILTIN_POLICIES = frozenset(
    {
        "PROXY",
        "DIRECT",
        "TAILSCALE",
        "REJECT",
        "REJECT-DICT",
        "REJECT-ARRAY",
        "REJECT-200",
        "REJECT-IMG",
        "REJECT-TINYGIF",
        "REJECT-VIDEO",
        "REJECT-DROP",
        "REJECT-NO-DROP",
    }
)
DOMAIN_RULE_TYPES = frozenset(
    {
        "DOMAIN",
        "DOMAIN-SUFFIX",
        "DOMAIN-KEYWORD",
        "DOMAIN-WILDCARD",
        "DOMAIN-SET",
        "USER-AGENT",
        "URL-REGEX",
    }
)
IP_RULE_TYPES = frozenset({"IP-CIDR", "IP-CIDR6", "IP-ASN", "GEOIP"})
OTHER_RULE_TYPES = frozenset({"RULE-SET", "SCRIPT", "DST-PORT", "AND", "OR", "NOT"})
LOGIC_RULE_TYPES = frozenset({"AND", "OR", "NOT"})
FINAL_RULE_TYPE = "FINAL"
NO_RESOLVE = "no-resolve"
REQUIRED_SECTIONS = ("General", "Rule")
SECTION_PATTERN = re.compile(r"^\[(.+)]$")
GROUP_PATTERN = re.compile(
    r"^(.+?)\s*=\s*(select|url-test|fallback|load-balance|random)\s*,(.*)$"
)
PLAINTEXT_DNS_PATTERN = re.compile(r"^(\d{1,3}(\.\d{1,3}){3}|system)$")
GROUP_OPTION_SEPARATOR = "="
REQUIRED_GENERAL = {
    "stun-response-ip": None,
    "stun-response-ipv6": None,
    "udp-policy-not-supported-behaviour": "REJECT",
    "dns-direct-system": "false",
}
HTTP_OK = 200
HTTP_TIMEOUT_SECONDS = 30
MIN_REMOTE_BYTES = 64


def parse_sections(text: str) -> dict[str, list[tuple[int, str]]]:
    """把配置拆成 {节名: [(行号, 去注释后的行)]}.

    Args:
        text: 配置文件全文.

    Returns:
        各节的有效行, 已剔除空行与 # 注释行.
    """
    sections: dict[str, list[tuple[int, str]]] = {}
    current = None
    for lineno, raw in enumerate(text.splitlines(), start=1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        matched = SECTION_PATTERN.match(line)
        if matched:
            current = matched.group(1)
            sections.setdefault(current, [])
            continue
        if current is not None:
            sections[current].append((lineno, line))
    return sections


def parse_general(lines: list[tuple[int, str]]) -> dict[str, str]:
    """解析 [General] 的 key = value."""
    general: dict[str, str] = {}
    for _, line in lines:
        key, sep, value = line.partition("=")
        if sep:
            general[key.strip()] = value.strip()
    return general


def parse_groups(lines: list[tuple[int, str]]) -> dict[str, list[str]]:
    """解析 [Proxy Group], 返回 {组名: 子策略列表(不含 key=value 参数)}."""
    groups: dict[str, list[str]] = {}
    for _, line in lines:
        matched = GROUP_PATTERN.match(line)
        if not matched:
            continue
        members = [
            m.strip()
            for m in matched.group(3).split(",")
            if GROUP_OPTION_SEPARATOR not in m
        ]
        groups[matched.group(1).strip()] = members
    return groups


def check_general(general: dict[str, str], errors: list[str]) -> None:
    """校验防泄漏相关的通用参数."""
    for key, expected in REQUIRED_GENERAL.items():
        actual = general.get(key)
        if actual is None:
            errors.append(f"[General] 缺少 {key}（防泄漏必需）")
        elif expected is not None and actual != expected:
            errors.append(f"[General] {key} 应为 {expected}，当前为 {actual}")
    for key in ("dns-server", "fallback-dns-server"):
        servers = [s.strip() for s in general.get(key, "system").split(",")]
        plaintext = [s for s in servers if PLAINTEXT_DNS_PATTERN.match(s)]
        if plaintext:
            errors.append(
                f"[General] {key} 含明文/系统 DNS {plaintext}，会让查询以明文暴露给 ISP"
            )


def check_rules(
    rules: list[tuple[int, str]], groups: dict[str, list[str]], errors: list[str]
) -> list[str]:
    """校验规则类型、策略引用、IP 规则 no-resolve 与 FINAL 位置.

    Returns:
        规则中引用的远程 URL 列表.
    """
    known_policies = BUILTIN_POLICIES | groups.keys()
    known_types = (
        DOMAIN_RULE_TYPES | IP_RULE_TYPES | OTHER_RULE_TYPES | {FINAL_RULE_TYPE}
    )
    urls: list[str] = []
    for index, (lineno, line) in enumerate(rules):
        rule_type = line.split(",", 1)[0].strip()
        if rule_type not in known_types:
            errors.append(f"第 {lineno} 行：未知规则类型 {rule_type}")
            continue
        if rule_type in LOGIC_RULE_TYPES:
            policy = line.rsplit("),", 1)[-1].split(",")[0].strip()
            options: list[str] = []
        else:
            fields = [f.strip() for f in line.split(",")]
            policy_index = 1 if rule_type == FINAL_RULE_TYPE else 2
            if len(fields) <= policy_index:
                errors.append(f"第 {lineno} 行：字段不足")
                continue
            policy = fields[policy_index]
            options = fields[policy_index + 1 :]
            if rule_type in {"RULE-SET", "DOMAIN-SET"}:
                urls.append(fields[1])
        if policy not in known_policies:
            errors.append(f"第 {lineno} 行：策略 {policy} 未定义")
        if rule_type in IP_RULE_TYPES and NO_RESOLVE not in options:
            errors.append(
                f"第 {lineno} 行：IP 类规则缺 no-resolve，会触发本地 DNS 解析导致泄漏"
            )
        if rule_type == FINAL_RULE_TYPE:
            if index != len(rules) - 1:
                errors.append(f"第 {lineno} 行：FINAL 必须是最后一条规则")
            if policy == "DIRECT" or "DIRECT" in groups.get(policy, []):
                errors.append(
                    f"第 {lineno} 行：FINAL 可落到 DIRECT，名单外域名会在本地解析"
                )
    if not rules or not rules[-1][1].startswith(FINAL_RULE_TYPE):
        errors.append("[Rule] 缺少结尾的 FINAL 规则")
    return urls


def check_remote(urls: list[str], errors: list[str]) -> None:
    """下载每个远程规则, 校验 HTTP 状态与内容非空."""
    for url in urls:
        try:
            with urllib.request.urlopen(url, timeout=HTTP_TIMEOUT_SECONDS) as resp:
                body = resp.read()
                status = resp.status
        except (urllib.error.URLError, TimeoutError) as exc:
            errors.append(f"远程规则不可达 {url}: {exc}")
            continue
        if status != HTTP_OK or len(body) < MIN_REMOTE_BYTES:
            errors.append(f"远程规则异常 {url}: HTTP {status}, {len(body)} 字节")
            continue
        logger.info("  OK %9d B  %s", len(body), url)


def main() -> int:
    """命令行入口."""
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("conf", nargs="?", type=Path, default=DEFAULT_CONF)
    parser.add_argument(
        "--online", action="store_true", help="同时下载并校验所有远程规则"
    )
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")

    sections = parse_sections(args.conf.read_text(encoding="utf-8"))
    errors: list[str] = [
        f"缺少 [{name}] 节" for name in REQUIRED_SECTIONS if name not in sections
    ]
    general = parse_general(sections.get("General", []))
    groups = parse_groups(sections.get("Proxy Group", []))
    check_general(general, errors)
    for name, members in groups.items():
        undefined = [
            m for m in members if m not in BUILTIN_POLICIES and m not in groups
        ]
        if undefined:
            errors.append(f"策略组 {name} 引用了未定义的策略 {undefined}")
    urls = check_rules(sections.get("Rule", []), groups, errors)
    if args.online:
        logger.info("校验 %d 个远程规则：", len(urls))
        check_remote(urls, errors)

    rule_count = len(sections.get("Rule", []))
    logger.info("规则 %d 条，策略组 %d 个，远程规则 %d 个", rule_count, len(groups), len(urls))
    for err in errors:
        logger.error("%s", err)
    if errors:
        logger.error("失败：%d 个问题", len(errors))
        return 1
    logger.info("通过")
    return 0


if __name__ == "__main__":
    sys.exit(main())
