# External Service Risk Watch

External Service Risk Watch は、システムで利用している外部サービス、API、SDKを監視します。既存のCVE Watchとは意図的に分離しています。

既存のCVE Watchは内部で利用しているパッケージの脆弱性を監視し、`docs/alerts.json` に出力します。本WatcherはSlack、Google Calendar、Microsoft Graph / Outlook Calendar、Microsoft Graph / Teams、ZoomのAPI利用範囲を監視し、`docs/external_service/` 配下にのみ出力します。

英語版READMEは [`README_EN.md`](README_EN.md) を参照してください。

## 監視範囲

API・セキュリティに関連する以下の変更を保持します。

- `VULNERABILITY`：脆弱性
- `SECURITY_ADVISORY`：セキュリティアドバイザリ
- `SECURITY_GUIDANCE`：セキュリティガイダンス
- `AUTH_CHANGE`：認証・認可に関する変更
- `BREAKING_CHANGE`：破壊的変更
- `DEPRECATION`：非推奨化・廃止予定

通常の機能追加・機能告知は、セキュリティ、認証、破壊的変更、非推奨化・廃止に関係する記述を含まない限り対象外とします。

## 情報源

実装では、無料で利用できる公開情報源とGitHub Actionsのホステッドランナーのみを使用します。

- NVD API 2.0（`NVD_API_KEY` secretが設定されている場合は既存のキーを利用）
- OSV API querybatch（`google/apiclient 2.12.6` および `microsoft/microsoft-graph 1.81.0`）
- Slack Developer Docs changelog RSS / Atom
- Google Calendar API release notes XML feed
- Microsoft Graph changelog HTMLページおよびMSRC CVRF metadata endpoint
- Zoom Developer Forum changelog RSS
- Zoom Security Bulletins HTMLページ

NVDは公開日時と最終更新日時の両方を条件として検索します。これにより、たとえば当初はDesktop Clientのみが影響対象とされていたCVEについて、後からVendor情報が更新されAPI利用範囲にも影響することが判明した場合に再評価できます。

Microsoft Graphには公開changelogページがあり、Microsoftからfilter可能なRSSの提供も告知されていますが、本実装では直接利用できるRSS URLが確認できていないため使用していません。代わりに、確認済みの公式changelogページをHTML adapterで監視します。

外部APIの監視ではNVDだけでは十分ではありません。重要なProviderからの通知がCVEとして登録されない場合があるためです。OAuthの挙動変更、セキュリティガイダンス、APIの破壊的変更、非推奨化・廃止も実装の安全性や可用性に影響する可能性があるため、Vendor提供のfeed等を独立して監視します。

## 関連性判定

関連性はルールベースで判定し、LLM APIは使用しません。

- `RELEVANT`：監視対象のサービス、endpoint、product、SDKへの影響が明確なイベント
- `REVIEW`：CVEまたはVendorには一致するものの、監視対象APIへの影響をルールだけでは確定できないイベント
- `NOT_RELEVANT`：現在の利用範囲外であることが明確なイベント。例：Zoom REST APIのみを利用している場合のZoom Workplace for Windowsに限定された脆弱性
- `INFORMATIONAL`：監視対象APIに一致する破壊的変更・非推奨化等で、直ちに脆弱性を意味しない情報

各レコードには判定理由、confidence、matched targetsを保持し、後から「なぜ対象に含めた／除外したのか」を確認できるようにします。

## JSONファイル

`alerts.json` には、人間による確認対象となる `RELEVANT`、`REVIEW`、`INFORMATIONAL` のレコードを保存します。

`history.json` には `NOT_RELEVANT` を含む履歴を保持し、重複排除、監査、Vendor情報更新時の再評価に利用します。

`state.json` にはsource adapterの状態を記録します。adapterのstatusは以下を区別します。

- `SUCCESS`
- `SUCCESS_NO_RESULTS`
- `FETCH_ERROR`
- `PARSE_ERROR`
- `SCHEMA_CHANGED`

取得またはparserで障害が発生した場合、単純に「対象情報0件」とは扱わずworkflowをfailureにします。

source adapterが失敗した場合でも、workflowは `state.json` をcommitした後、最後のstepでjobをfailureにします。これにより、異常な実行を成功扱いすることなく、repository上に障害理由を残します。

`alerts.json` と `history.json` はsemanticな内容に変更がない場合、既存の `generated_at` を維持します。`state.json` は実行ごとの状態記録として更新されます。

## 設定

監視対象は `config/external_services.json` で設定します。

Python標準ライブラリのみで実行できるよう、設定形式にはJSONを使用しています。サービスを追加する場合は、以下の情報を持つservice entryを追加します。

- `key`
- `vendor_keywords`
- `products`
- `endpoints`
- `keywords`
- `exclude_keywords`
- 必要に応じて `sdk`
- 情報源URL

## 自動実行

`.github/workflows/external-service-watch.yml` は毎日 `21:17 UTC` に実行されます。また、`workflow_dispatch` による手動実行も可能です。

workflowは変更がある場合に以下のファイルのみをcommitします。

- `docs/external_service/alerts.json`
- `docs/external_service/history.json`
- `docs/external_service/state.json`

## ローカル実行

```bash
python scripts/external_service/run.py
```

network accessを行わずにテストを実行する場合：

```bash
python -m unittest discover -s tests
```

## 無料運用

本Watcherには、**追加費用 `¥0`** という必須の非機能要件があります。

public GitHub repository、GitHub Actionsの標準ホステッドランナー、Providerが公開しているfeed / page、NVD、OSV、JVN互換parser、およびPython標準ライブラリのみを利用します。

本実装は検証用PoCであり、情報の完全性・正確性・最新性・可用性を保証するものではありません。正式な継続運用、精度向上、監視対象追加、障害対応等を必要とする場合は、別途運用体制および必要なリソースを検討してください。
