# Operate CVE Notification

## English

This repository monitors vulnerability information that may affect the
technologies used by the operation environment, then publishes the matched
results as JSON.

The main script is [`scripts/watch.py`](scripts/watch.py). It fetches recent
vulnerability entries from NVD and JVN, filters them by configured keywords,
normalizes the records into a shared alert format, and writes the result to
[`docs/alerts.json`](docs/alerts.json).

### What It Watches

The watcher currently checks two sources:

- **NVD CVE API v2.0**
- **MyJVN `getVulnOverviewList` API**

For both sources, the script collects:

- vulnerabilities published in the last 30 days
- vulnerabilities modified or updated in the last 30 days

This is intended to catch both newly announced vulnerabilities and older
vulnerability records that were updated after initial publication.

### Monitored Keywords

The configured keywords cover these broad areas:

- **OS:** AlmaLinux, Red Hat Enterprise Linux, RHEL
- **JavaScript:** npm, Node.js, Vue, Vue.js, Vuetify
- **PHP:** composer, Laravel, Symfony, AuraSQL
- **Database:** PostgreSQL, pgAdmin
- **Web server:** Apache HTTP Server, Apache Tomcat, Apache

NVD and JVN have separate keyword lists and category maps in
[`scripts/watch.py`](scripts/watch.py), because their search and description
formats differ.

### Output

The generated file is [`docs/alerts.json`](docs/alerts.json). Its top-level
structure is:

```json
{
  "generated_at": "2026-05-21T03:31:14.275138+00:00",
  "count": 51,
  "sources": {
    "NVD": 30,
    "JVN": 21
  },
  "alerts": []
}
```

Each alert contains fields such as:

- `alert_id`: stable deduplication key
- `source`: `NVD` or `JVN`
- `category`: `OS`, `JS`, `PHP`, `DB`, `WEB`, or `UNKNOWN`
- `priority`: derived from severity
- `cve_id`
- `matched`: matched keyword
- `severity`
- `score`
- `published`
- `last_modified`
- `title`
- `description`
- `url`

Priorities are mapped from severity as follows:

- `CRITICAL` -> `URGENT`
- `HIGH` -> `WATCH`
- `MEDIUM` -> `NOTICE`
- `LOW` -> `LOW`
- anything else -> `INFO`

### Automation

[`cve-watch.yml`](.github/workflows/cve-watch.yml) runs the watcher with
GitHub Actions:

- every 6 hours
- manually via `workflow_dispatch`

When [`docs/alerts.json`](docs/alerts.json) changes, the workflow commits the
updated JSON back to the repository with the message `Update CVE alerts`.

### Running Locally

The script uses only the Python standard library.

```bash
python scripts/watch.py
```

Running it updates [`docs/alerts.json`](docs/alerts.json).

### Customization

To change what is monitored, edit the keyword and category lists in
[`scripts/watch.py`](scripts/watch.py):

- `NVD_KEYWORDS`
- `NVD_CATEGORY_MAP`
- `JVN_KEYWORDS`
- `JVN_CATEGORY_MAP`

To change the lookback window, edit:

- `NVD_LOOKBACK_DAYS`
- `JVN_LOOKBACK_DAYS`

## 日本語

このリポジトリは、運用環境で利用している可能性のある技術に関連する脆弱性情報を監視し、該当した結果を JSON として出力するためのものです。

中心となるスクリプトは [`scripts/watch.py`](scripts/watch.py) です。NVD と JVN から直近の脆弱性情報を取得し、設定されたキーワードに一致するものを抽出し、共通のアラート形式に整形して [`docs/alerts.json`](docs/alerts.json) に書き出します。

### 監視対象

現在は次の2つの情報源を確認しています。

- **NVD CVE API v2.0**
- **MyJVN `getVulnOverviewList` API**

どちらの情報源についても、次の両方を取得します。

- 直近30日に公開された脆弱性
- 直近30日に更新された脆弱性

新規公開された脆弱性だけでなく、公開後に内容が更新された既存の脆弱性も拾うことを意図しています。

### 監視キーワード

設定されているキーワードは、おおまかに次の分類を対象にしています。

- **OS:** AlmaLinux, Red Hat Enterprise Linux, RHEL
- **JavaScript:** npm, Node.js, Vue, Vue.js, Vuetify
- **PHP:** composer, Laravel, Symfony, AuraSQL
- **データベース:** PostgreSQL, pgAdmin
- **Webサーバー:** Apache HTTP Server, Apache Tomcat, Apache

NVD と JVN では検索方法や説明文の形式が異なるため、[`scripts/watch.py`](scripts/watch.py) 内でそれぞれ別のキーワードリストとカテゴリマップを持っています。

### 出力内容

生成されるファイルは [`docs/alerts.json`](docs/alerts.json) です。トップレベルの構造は次のようになっています。

```json
{
  "generated_at": "2026-05-21T03:31:14.275138+00:00",
  "count": 51,
  "sources": {
    "NVD": 30,
    "JVN": 21
  },
  "alerts": []
}
```

各アラートには、主に次の項目が含まれます。

- `alert_id`: 重複除外用の安定したキー
- `source`: `NVD` または `JVN`
- `category`: `OS`, `JS`, `PHP`, `DB`, `WEB`, `UNKNOWN` のいずれか
- `priority`: 深刻度から算出した優先度
- `cve_id`
- `matched`: 一致したキーワード
- `severity`
- `score`
- `published`
- `last_modified`
- `title`
- `description`
- `url`

優先度は深刻度から次のように変換されます。

- `CRITICAL` -> `URGENT`
- `HIGH` -> `WATCH`
- `MEDIUM` -> `NOTICE`
- `LOW` -> `LOW`
- その他 -> `INFO`

### 自動実行

[`cve-watch.yml`](.github/workflows/cve-watch.yml) により、GitHub Actions で watcher が実行されます。

- 6時間ごとの定期実行
- `workflow_dispatch` による手動実行

[`docs/alerts.json`](docs/alerts.json) に変更がある場合、workflow が `Update CVE alerts` というコミットメッセージで更新結果をリポジトリへコミットします。

### ローカル実行

このスクリプトは Python の標準ライブラリのみで動作します。

```bash
python scripts/watch.py
```

実行すると [`docs/alerts.json`](docs/alerts.json) が更新されます。

### カスタマイズ

監視対象を変更する場合は、[`scripts/watch.py`](scripts/watch.py) のキーワードとカテゴリ定義を編集します。

- `NVD_KEYWORDS`
- `NVD_CATEGORY_MAP`
- `JVN_KEYWORDS`
- `JVN_CATEGORY_MAP`

取得対象期間を変更する場合は、次の値を編集します。

- `NVD_LOOKBACK_DAYS`
- `JVN_LOOKBACK_DAYS`
