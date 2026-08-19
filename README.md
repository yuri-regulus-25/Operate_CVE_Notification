# Operate CVE Notification

## English

This repository monitors vulnerability information that may affect the
technologies used by the operation environment, then publishes the matched
results as JSON.

The main collection script is [`scripts/watch.py`](scripts/watch.py). It fetches
recent vulnerability entries from NVD and JVN, filters them by configured
keywords, normalizes the records into a shared alert format, and writes the
result to [`docs/alerts.json`](docs/alerts.json).

The GitHub Actions workflow runs [`scripts/enrich_alerts.py`](scripts/enrich_alerts.py),
which calls `watch.py` first and then enriches the generated alerts with
reporting-oriented classification fields such as the actual affected product,
package name, ecosystem, relation type, and noise risk.

### What It Watches

The watcher currently checks two sources:

- **NVD CVE API v2.0**
- **MyJVN `getVulnOverviewList` API**

For both sources, the script collects:

- vulnerabilities published in the last 15 days
- vulnerabilities modified or updated in the last 15 days

This is intended to catch both newly announced vulnerabilities and older
vulnerability records that were updated after initial publication. The script
does not filter by CVSS score or severity; matching is based on the configured
keywords.

### Monitored Keywords

The configured keywords cover these broad areas:

- **OS:** AlmaLinux, Red Hat Enterprise Linux, RHEL
- **JavaScript:** npm, Node.js, Vue, Vue.js, Vuetify
- **PHP:** composer, Laravel, Symfony, AuraSQL
- **Database:** PostgreSQL, pgAdmin
- **Web server / Network:** Apache HTTP Server, Apache Tomcat, Apache, IIS, SMB, RDP, Active Directory, LDAP
- **Windows components:** Windows Server, Windows Kernel, Win32k, CLFS, BitLocker, Hyper-V, Microsoft Defender

NVD and JVN use the same broad watch terms. The initial matching logic lives in
[`scripts/watch.py`](scripts/watch.py), while reporting-oriented enrichment lives
in [`scripts/enrich_alerts.py`](scripts/enrich_alerts.py).

### Output

The generated file is [`docs/alerts.json`](docs/alerts.json). Its top-level
structure is:

```json
{
  "generated_at": "2026-05-21T03:31:14.275138+00:00",
  "count": 948,
  "sources": {
    "NVD": 240,
    "JVN": 708
  },
  "alerts": []
}
```

Each alert contains the original normalized fields:

- `alert_id`: stable deduplication key
- `source`: `NVD` or `JVN`
- `category`: `OS`, `JS`, `PHP`, `DB`, `WEB`, or `UNKNOWN`
- `product_key`: coarse product key selected by the watcher
- `confidence`: classification confidence or match source
- `priority`: derived from severity
- `cve_id`
- `matched`: coarse matched product or keyword
- `severity`
- `score`
- `published`
- `last_modified`
- `title`
- `description`
- `url`

After enrichment, each alert also contains reporting-oriented fields:

- `actual_product`: product, component, or package that appears to be the actual affected target
- `package_name`: package name that can be checked in lock files, when known
- `ecosystem`: broader technology area such as `Composer / PHP`, `npm / Node.js`, or `PostgreSQL ecosystem`
- `relation_type`: relationship between the alert and the monitored technology
- `classification_reason`: why the enrichment logic selected the target
- `tracked_keyword`: watch keyword found in the title or description
- `noise_risk`: `low`, `medium`, or `high` estimate for false-positive / misclassification risk

The original `product_key` and `matched` fields are kept for backward
compatibility. Department-facing reports should prefer `actual_product`,
`package_name`, `ecosystem`, `relation_type`, and `noise_risk`.

### Relation Types

`relation_type` is intended to make downstream triage easier:

- `direct_product`: the product itself appears to be affected
- `direct_package`: a specific package appears to be affected
- `ecosystem_package`: a package or tool in a monitored ecosystem appears to be affected
- `runtime_context`: the monitored technology is a runtime or execution context
- `keyword_only`: no stronger target could be inferred; review before forwarding broadly

### Priorities

Priorities are mapped from severity as follows:

- `CRITICAL` -> `URGENT`
- `HIGH` -> `WATCH`
- `MEDIUM` -> `NOTICE`
- `LOW` -> `LOW`
- anything else -> `INFO`

### Automation

[`cve-watch.yml`](.github/workflows/cve-watch.yml) runs the enriched watcher with
GitHub Actions:

- hourly, at minute 23
- manually via `workflow_dispatch`

When [`docs/alerts.json`](docs/alerts.json) changes, the workflow commits the
updated JSON back to the repository with the message `Update CVE alerts`.

### Running Locally

The scripts use only the Python standard library.

```bash
python scripts/enrich_alerts.py
```

This runs `watch.py`, enriches the generated alerts, and updates
[`docs/alerts.json`](docs/alerts.json).

If you only want the raw watcher output without enrichment:

```bash
python scripts/watch.py
```

### Customization

To change what is monitored, edit the keyword and product rules in
[`scripts/watch.py`](scripts/watch.py):

- `KEYWORD_GROUPS`
- `PRODUCT_RULES`
- `NVD_KEYWORDS`
- `JVN_KEYWORDS`

To tune reporting-oriented classification, edit
[`scripts/enrich_alerts.py`](scripts/enrich_alerts.py):

- `KNOWN_PRODUCTS`
- `ECOSYSTEM_BY_CATEGORY`
- `NOISE_HINTS`

To change the lookback window, edit:

- `NVD_LOOKBACK_DAYS`
- `JVN_LOOKBACK_DAYS`

If a GitHub Actions secret named `NVD_API_KEY` is configured, the workflow uses
it for the NVD API. Without it, the script slows NVD requests to respect the
public rate limit.

## 日本語

このリポジトリは、運用環境で利用している可能性のある技術に関連する脆弱性情報を監視し、該当した結果を JSON として出力するためのものです。

中心となる取得スクリプトは [`scripts/watch.py`](scripts/watch.py) です。NVD と JVN から直近の脆弱性情報を取得し、設定されたキーワードに一致するものを抽出し、共通のアラート形式に整形して [`docs/alerts.json`](docs/alerts.json) に書き出します。

GitHub Actions では [`scripts/enrich_alerts.py`](scripts/enrich_alerts.py) を実行します。このスクリプトは `watch.py` を呼び出したあと、生成されたアラートに対して、実際の対象製品、パッケージ名、エコシステム、関係区分、ノイズリスクなど、他部署展開やレビュー資料で使いやすい分類項目を追加します。

### 監視対象

現在は次の2つの情報源を確認しています。

- **NVD CVE API v2.0**
- **MyJVN `getVulnOverviewList` API**

どちらの情報源についても、次の両方を取得します。

- 直近15日に公開された脆弱性
- 直近15日に更新された脆弱性

新規公開された脆弱性だけでなく、公開後に内容が更新された既存の脆弱性も拾うことを意図しています。CVSSスコアや深刻度による除外は行わず、設定されたキーワードへの一致を基準に出力します。

### 監視キーワード

設定されているキーワードは、おおまかに次の分類を対象にしています。

- **OS:** AlmaLinux, Red Hat Enterprise Linux, RHEL
- **JavaScript:** npm, Node.js, Vue, Vue.js, Vuetify
- **PHP:** composer, Laravel, Symfony, AuraSQL
- **データベース:** PostgreSQL, pgAdmin
- **Webサーバー / ネットワーク:** Apache HTTP Server, Apache Tomcat, Apache, IIS, SMB, RDP, Active Directory, LDAP
- **Windowsコンポーネント:** Windows Server, Windows Kernel, Win32k, CLFS, BitLocker, Hyper-V, Microsoft Defender

NVD と JVN では同じ広めの監視キーワードを利用します。一次的な検索・抽出ロジックは [`scripts/watch.py`](scripts/watch.py)、他部署展開向けの分類補強は [`scripts/enrich_alerts.py`](scripts/enrich_alerts.py) にあります。

### 出力内容

生成されるファイルは [`docs/alerts.json`](docs/alerts.json) です。トップレベルの構造は次のようになっています。

```json
{
  "generated_at": "2026-05-21T03:31:14.275138+00:00",
  "count": 948,
  "sources": {
    "NVD": 240,
    "JVN": 708
  },
  "alerts": []
}
```

各アラートには、従来の正規化項目として主に次の項目が含まれます。

- `alert_id`: 重複除外用の安定したキー
- `source`: `NVD` または `JVN`
- `category`: `OS`, `JS`, `PHP`, `DB`, `WEB`, `UNKNOWN` のいずれか
- `product_key`: watcher が選択した大まかなプロダクトキー
- `confidence`: 分類の信頼度または一致元
- `priority`: 深刻度から算出した優先度
- `cve_id`
- `matched`: 大まかな一致プロダクトまたはキーワード
- `severity`
- `score`
- `published`
- `last_modified`
- `title`
- `description`
- `url`

enrichment 後は、さらに次の項目が追加されます。

- `actual_product`: 実際に脆弱性の対象と考えられる製品・コンポーネント・パッケージ
- `package_name`: lockファイル等で照合しやすいパッケージ名。判定できる場合のみ設定
- `ecosystem`: `Composer / PHP`, `npm / Node.js`, `PostgreSQL ecosystem` などの大分類
- `relation_type`: 監視対象技術との関係区分
- `classification_reason`: その分類にした根拠
- `tracked_keyword`: title または description に含まれていた監視キーワード
- `noise_risk`: 誤分類・ノイズの可能性を `low`, `medium`, `high` で表したもの

既存互換のため、`product_key` と `matched` は引き続き出力します。ただし、開発部門・インフラ部門へ展開する資料では、`actual_product`, `package_name`, `ecosystem`, `relation_type`, `noise_risk` を優先して利用する想定です。

### relation_type の意味

`relation_type` は後続の確認・展開をしやすくするための区分です。

- `direct_product`: 製品本体が脆弱性の対象と考えられる
- `direct_package`: 特定パッケージが脆弱性の対象と考えられる
- `ecosystem_package`: 監視対象エコシステム内のパッケージ・ツールが対象と考えられる
- `runtime_context`: 監視対象技術が実行環境・利用文脈として関係する
- `keyword_only`: 強い対象判定ができず、キーワード一致のみ。広く展開する前に確認推奨

### 優先度

優先度は深刻度から次のように変換されます。

- `CRITICAL` -> `URGENT`
- `HIGH` -> `WATCH`
- `MEDIUM` -> `NOTICE`
- `LOW` -> `LOW`
- その他 -> `INFO`

### 自動実行

[`cve-watch.yml`](.github/workflows/cve-watch.yml) により、GitHub Actions で enriched watcher が実行されます。

- 毎時23分の定期実行
- `workflow_dispatch` による手動実行

[`docs/alerts.json`](docs/alerts.json) に変更がある場合、workflow が `Update CVE alerts` というコミットメッセージで更新結果をリポジトリへコミットします。

### ローカル実行

このスクリプトは Python の標準ライブラリのみで動作します。

```bash
python scripts/enrich_alerts.py
```

実行すると `watch.py` による取得後、enrichment を行い、[`docs/alerts.json`](docs/alerts.json) が更新されます。

分類補強なしの生の watcher 出力だけを確認したい場合は、次を実行します。

```bash
python scripts/watch.py
```

### カスタマイズ

監視対象を変更する場合は、[`scripts/watch.py`](scripts/watch.py) のキーワードとプロダクト定義を編集します。

- `KEYWORD_GROUPS`
- `PRODUCT_RULES`
- `NVD_KEYWORDS`
- `JVN_KEYWORDS`

他部署展開向けの分類補強を調整する場合は、[`scripts/enrich_alerts.py`](scripts/enrich_alerts.py) を編集します。

- `KNOWN_PRODUCTS`
- `ECOSYSTEM_BY_CATEGORY`
- `NOISE_HINTS`

取得対象期間を変更する場合は、次の値を編集します。

- `NVD_LOOKBACK_DAYS`
- `JVN_LOOKBACK_DAYS`

GitHub Actions の secret に `NVD_API_KEY` を設定している場合、NVD API の呼び出しに利用されます。未設定の場合は、公開レート制限に合わせて NVD へのリクエスト間隔を長めに取ります。

## External Service Risk Watch

外部サービス/API/SDK 向けの監視は、既存 CVE Watch とは分離して
[`docs/external_service/README.md`](docs/external_service/README.md) に記載しています。

- workflow: [`.github/workflows/external-service-watch.yml`](.github/workflows/external-service-watch.yml)
- target config: [`config/external_services.json`](config/external_services.json)
- output: [`docs/external_service/alerts.json`](docs/external_service/alerts.json),
  [`docs/external_service/history.json`](docs/external_service/history.json),
  [`docs/external_service/state.json`](docs/external_service/state.json)
