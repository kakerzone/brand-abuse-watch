> 面向任意 AI Agent、自动化平台或人工安全团队复用的品牌仿冒监控 Skill 与 Python 工具包。

# Brand Abuse Watch

[English](#english) · [中文](#中文)

---

## English

### Overview

**Brand Abuse Watch** is an evidence-first, standalone Python toolkit for defensive brand-protection work. It helps security, trust-and-safety, legal, and operations teams discover and review lookalike domains and possible unauthorized brand use.

The toolkit deliberately separates discovery from evidence collection and human decision-making. A similar domain name, active DNS record, certificate, shared IP address, or keyword match is a signal—not proof of fraud or impersonation.

### Capabilities

| Capability | What it provides |
| --- | --- |
| Brand profiles | One review-required profile per brand, including aliases, official domains, risk terms, allowlists, and optional visual/IP indicators. |
| Candidate discovery | Deterministic typo, Unicode-confusable, prefix/suffix, concatenated, subdomain, and TLD variants. |
| Public evidence collection | Bounded, unauthenticated DNS, HTTP header/title, RDAP, and certificate-transparency collection when network access is explicitly authorized. |
| Scoring | Independent `brand_similarity`, `abuse_likelihood`, and `evidence_completeness`; the combined score is triage only. |
| Correlation and tracking | Optional infrastructure correlation and snapshot comparison that reports additions and material changes. |
| Review workflow | Local queries, case worklists, reviewer statuses, false-positive reasons, and evidence-package generation. |
| Lark delivery | Optional, deduplicated Chinese or English interactive cards with direct public-evidence links. |

### Safety boundaries

This repository is for defensive monitoring and internal review. It does **not**:

- automatically report domains, request takedowns, block traffic, or contact domain owners;
- log in, submit forms, upload files, download content, or execute site JavaScript;
- treat missing evidence as a clean result;
- classify a domain as malicious solely because its name resembles a brand.

External reporting, takedown, blocking, or outreach requires explicit human approval and must follow the organization’s legal and security process.

### Requirements

- Python 3.9 or later.
- Network access only for collection steps that are explicitly authorized.
- Optional: [`dnstwist`](https://github.com/elceef/dnstwist) for deeper typo-permutation discovery.

Core scripts are standard-library oriented. Install the optional dependency only when needed:

```bash
python3 -m pip install dnstwist
```

### Install

Clone the repository and run the scripts directly from the repository root:

```bash
git clone <your-repository-url>
cd brand-abuse-watch

# Optional but recommended: isolate optional dependencies.
python3 -m venv .venv
source .venv/bin/activate
```

All discovery, collection, scoring, tracking, evidence, and notification scripts run directly from this repository.

### Quick start

#### 1. Create a protected-brand profile

Use only a brand and official site that you are authorized to assess. The generated profile is deliberately marked for review before operational use.

```bash
mkdir -p profiles

python3 scripts/init_brand_profile.py \
  --name "Example Brand" \
  --brand-id example-brand \
  --website https://example.com \
  --alias examplebrand \
  --risk-keyword login \
  --risk-keyword payment \
  --risk-keyword wallet \
  --output profiles/example-brand.json

python3 scripts/validate_profiles.py --profiles profiles
```

Review aliases, official infrastructure, allowlists, relevant countries/TLDs, and risk vocabulary before continuing.

#### 2. Discover candidates

Discovery is offline and deterministic. It creates names for review; it does not prove that those domains exist or are malicious.

```bash
python3 scripts/discover_profiles.py \
  --profiles profiles \
  --output candidates.jsonl
```

#### 3. Collect bounded public evidence

Run network collection only after approval. The built-in enricher is unauthenticated and bounded, starting with higher-priority candidates.

```bash
python3 scripts/brand_monitor.py enrich \
  --input candidates.jsonl \
  --output enriched.jsonl \
  --network \
  --limit 50
```

Optional public collectors can run separately when their source, rate limit, and evidence scope are appropriate:

```bash
python3 scripts/collect_public_intel.py rdap \
  --input enriched.jsonl \
  --output rdap-evidence.jsonl \
  --network \
  --limit 50

python3 scripts/collect_dnstwist.py \
  --profiles profiles \
  --output dnstwist-findings.jsonl \
  --network
```

#### 4. Rescore, track, and report

```bash
python3 scripts/rescore_findings.py \
  --input enriched.jsonl \
  --profiles profiles \
  --output rescored.jsonl

python3 scripts/brand_monitor.py track \
  --input rescored.jsonl \
  --state monitor-state.json \
  --changes changes.jsonl

python3 scripts/brand_monitor.py report \
  --input rescored.jsonl \
  --changes changes.jsonl \
  --output report.md
```

### Risk interpretation

The score prioritizes review; it is not a maliciousness verdict. Keep these values distinct:

| Signal | Meaning |
| --- | --- |
| `brand_similarity` | How closely a domain, page, logo, or Unicode form resembles the protected brand. |
| `abuse_likelihood` | How strongly the available evidence indicates phishing, fraud, impersonation, or malicious delivery. |
| `evidence_completeness` | How much of the planned collection actually succeeded. Missing data must remain visible. |

For example, a recent one-character typo with public DNS can warrant tracking while still lacking enough evidence to call it an impersonation site. An accessible page using the brand name with a payment or login flow can justify expedited human review.

### Optional Lark alerts

Lark delivery is opt-in. Store webhooks and signing secrets in environment variables or an approved secret store—never in a profile, finding, script, commit, issue, or screenshot.

```bash
export LARK_WEBHOOK_URL="https://open.larksuite.com/open-apis/bot/v2/hook/<webhook-id>"
export LARK_WEBHOOK_SECRET="<signing-secret>"
```

Preview before delivery:

```bash
python3 scripts/notify_lark.py \
  --input rescored.jsonl \
  --profiles profiles \
  --state lark-alert-state.json \
  --preview lark-preview.jsonl \
  --language zh
```

Add `--send` only after a human has approved both the card and its destination. A verified context file can add a business-readable conclusion, scope, recommendation, and clickable evidence links. See [references/lark-alerts.md](references/lark-alerts.md).

### Repository layout

```text
brand-abuse-watch/
├── README.md                # Project documentation
├── assets/                  # Reusable profile template
├── scripts/                 # Discovery, collection, scoring, tracking, and alert helpers
└── references/              # Focused evidence, scoring, tracking, Lark, and governance guides
```

### Data handling and limitations

- Preserve raw provider exports, timestamps, source attribution, and parsing failures when using external adapters.
- A scan cannot enumerate the Internet: domains may be unindexed, IPv6/CNAME-only, rotating infrastructure, or access-restricted.
- DNS, RDAP, certificates, IPs, and web pages change. Record observation time.
- Shared infrastructure is a correlation signal, not proof of common ownership or campaign attribution.
- Do not commit real brand profiles, findings, captures, state files, databases, or evidence packages to a public repository unless they have been sanitized and approved.

The supplied `.gitignore` excludes virtual environments, `.env` files, generated scan artifacts, captures, state, and local databases.

### Further documentation

- [SKILL.md](SKILL.md): operating modes, safeguards, and workflow.
- [references/brand-profile.md](references/brand-profile.md): profile fields and review requirements.
- [references/scoring.md](references/scoring.md): risk-signal interpretation.
- [references/evidence-schema.md](references/evidence-schema.md): normalized evidence format.
- [references/lark-alerts.md](references/lark-alerts.md): card and delivery boundary.
- [references/governance.md](references/governance.md): reviewer, retention, and audit guidance.

---

## 中文

### 项目简介

**Brand Abuse Watch** 是一个独立运行、证据优先的 Python 品牌保护工具，用于发现、核验与持续跟踪相似域名、疑似仿冒站和未授权品牌使用线索。它适合安全、风控、法务、信任与安全及运营团队做防御性排查。

它强调“证据优先”：相似域名、DNS 解析、证书、共用 IP 或关键词都只是风险信号，不等于仿冒或诈骗结论。系统将候选生成、公开证据采集、风险排序和人工决策分开处理，避免把未知误判为恶意。

### 核心能力

| 能力 | 说明 |
| --- | --- |
| 多品牌档案 | 每个受保护品牌独立建档，可维护别名、官网、白名单、风险词及可选的 IP/视觉线索。 |
| 相似域名发现 | 离线生成拼写错误、Unicode 同形、前后缀、连字符、组合词、子域名和常见 TLD 变体。 |
| 公开证据采集 | 在明确授权网络访问后，进行有边界、无登录的 DNS、HTTP 标头/标题、RDAP 与证书透明度核验。 |
| 可解释评分 | 分开维护品牌相似度、滥用可能性和证据完整度；总分只用于排查排序。 |
| 关联与跟踪 | 可按基础设施线索关联，并对比扫描快照，仅报告新增和实质变化。 |
| 人工复核 | 支持查询、案件工作清单、复核状态、误报原因与证据包。 |
| Lark 通知 | 可选发送中文或英文交互式卡片，并保留可点击公开证据链接。 |

### 安全与权限边界

本项目只用于防御性监控和内部人工复核，默认不会：

- 自动向注册商、托管商、搜索引擎或监管机构投诉；
- 自动申请下架、拦截流量、封禁域名或联系域名所有人；
- 登录网站、提交表单、上传文件、下载内容或执行页面 JavaScript；
- 因证据缺失就认定站点安全；
- 因域名相似就认定站点恶意。

任何投诉、下架、封禁或外部沟通，都必须经过明确授权，并遵循公司法务、安全和应急响应流程。

### 环境要求

- Python 3.9 或更高版本。
- 只有在明确授权时才使用网络进行公开证据采集。
- 可选安装 [`dnstwist`](https://github.com/elceef/dnstwist)，用于更深度的拼写变体发现。

核心脚本尽量只依赖 Python 标准库；需要启用 dnstwist 时再安装：

```bash
python3 -m pip install dnstwist
```

### 安装

克隆仓库后，可直接在仓库根目录运行脚本：

```bash
git clone <你的仓库地址>
cd brand-abuse-watch

# 可选但建议：隔离可选依赖。
python3 -m venv .venv
source .venv/bin/activate
```

所有发现、采集、评分、跟踪、证据和通知脚本均可直接在本仓库内运行。

### 快速开始

#### 1. 创建品牌档案

只对已获授权的品牌和官网创建档案。生成后的档案默认需要人工检查后再投入运行。

```bash
mkdir -p profiles

python3 scripts/init_brand_profile.py \
  --name "示例品牌" \
  --brand-id example-brand \
  --website https://example.com \
  --alias examplebrand \
  --risk-keyword login \
  --risk-keyword payment \
  --risk-keyword wallet \
  --output profiles/example-brand.json

python3 scripts/validate_profiles.py --profiles profiles
```

继续前，应人工确认品牌别名、官网基础设施、白名单、关注国家/TLD 与风险词。

#### 2. 生成候选域名

候选发现为离线、确定性流程，只生成待核验名称；它不代表这些域名存在，更不代表恶意。

```bash
python3 scripts/discover_profiles.py \
  --profiles profiles \
  --output candidates.jsonl
```

#### 3. 采集有限公开证据

网络采集必须在获得授权后才执行。内置采集器为无登录、有数量上限的公开检查，并优先处理高优先级候选。

```bash
python3 scripts/brand_monitor.py enrich \
  --input candidates.jsonl \
  --output enriched.jsonl \
  --network \
  --limit 50
```

当数据源、速率和证据范围适合时，可单独执行公开采集器：

```bash
python3 scripts/collect_public_intel.py rdap \
  --input enriched.jsonl \
  --output rdap-evidence.jsonl \
  --network \
  --limit 50

python3 scripts/collect_dnstwist.py \
  --profiles profiles \
  --output dnstwist-findings.jsonl \
  --network
```

#### 4. 重评分、持续跟踪并生成报告

```bash
python3 scripts/rescore_findings.py \
  --input enriched.jsonl \
  --profiles profiles \
  --output rescored.jsonl

python3 scripts/brand_monitor.py track \
  --input rescored.jsonl \
  --state monitor-state.json \
  --changes changes.jsonl

python3 scripts/brand_monitor.py report \
  --input rescored.jsonl \
  --changes changes.jsonl \
  --output report.md
```

### 如何理解评分

评分用于帮助团队决定先查什么，不是恶意定性。报告与通知卡片应分别保留以下三类信息：

| 字段 | 含义 |
| --- | --- |
| `brand_similarity` | 域名、页面、Logo 或 Unicode 表示与受保护品牌的接近程度。 |
| `abuse_likelihood` | 现有证据对钓鱼、诈骗、仿冒或恶意投递的指向程度。 |
| `evidence_completeness` | 计划中的证据采集实际完成了多少；证据缺失必须如实展示。 |

例如，一个刚注册且少一个字母的活跃域名可以进入观察队列，但在没有页面、品牌文案、支付/登录流程或传播证据前，不应直接定性为仿冒。相反，若可访问页面冒用品牌并包含支付或登录流程，则应优先人工复核。

### 可选 Lark 通知

Lark 推送是可选能力。Webhook 与签名 Secret 必须通过环境变量或公司认可的密钥管理方式提供，绝不能写入品牌档案、扫描结果、脚本、提交记录、Issue 或截图。

```bash
export LARK_WEBHOOK_URL="https://open.larksuite.com/open-apis/bot/v2/hook/<webhook-id>"
export LARK_WEBHOOK_SECRET="<signing-secret>"
```

建议先生成预览：

```bash
python3 scripts/notify_lark.py \
  --input rescored.jsonl \
  --profiles profiles \
  --state lark-alert-state.json \
  --preview lark-preview.jsonl \
  --language zh
```

仅在确认卡片内容和目标群后才添加 `--send`。已核验上下文文件可加入业务可读的结论、范围说明、下一步建议及可点击证据链接；详见 [references/lark-alerts.md](references/lark-alerts.md)。

### 目录结构

```text
brand-abuse-watch/
├── README.md                # 项目说明（本文件）
├── assets/                  # 品牌档案模板
├── scripts/                 # 发现、采集、评分、跟踪和通知脚本
└── references/              # 证据、评分、跟踪、Lark 与治理说明
```

### 数据处理与局限

- 接入外部数据源时，应保留原始导出、采集时间、来源归属和解析失败信息。
- 单次扫描不可能枚举整个互联网：域名可能未被索引、仅使用 IPv6/CNAME、轮换基础设施，或限制访问。
- DNS、RDAP、证书、IP 与页面内容都会变化，必须记录观测时间。
- 共用基础设施只能作为关联线索，不能单独证明同一所有者或同一攻击活动。
- 除非经过脱敏和批准，不要将品牌档案、扫描结果、页面抓取、状态文件、数据库或证据包提交到公开仓库。

`.gitignore` 已默认排除虚拟环境、`.env`、扫描结果、页面抓取、状态文件和本地数据库。

### 延伸文档

- [SKILL.md](SKILL.md)：运行模式、必要防护与本地工作流。
- [references/brand-profile.md](references/brand-profile.md)：品牌档案字段与复核要求。
- [references/scoring.md](references/scoring.md)：风险信号与评分解释。
- [references/evidence-schema.md](references/evidence-schema.md)：标准化证据结构。
- [references/lark-alerts.md](references/lark-alerts.md)：Lark 卡片与发送边界。
- [references/governance.md](references/governance.md)：复核、留存和审计建议。
