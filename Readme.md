# フォーム自動送信ツール

- マルチスレッド送信
- プロキシ（HTTP/HTTPS/SOCKS）ローテーション
- ユーザーエージェントローテーション
- ランダム文字列/“バグ文字”の生成
- JSON 直POST（/api/bunko）またはフォーム投稿の両対応


## 必要要件
- Python 3.13.x

## セットアップ

2. 依存パッケージをインストール
   - バッチを使う場合（推奨）:
     ```batch
     PackageInstaller.bat
     ```
   - 直接 pip の場合:
     ```powershell
     python -m pip install -r requirements.txt
     ```

   注: SOCKS プロキシを使う場合は `PySocks` が必要です（requirements.txt に含まれています）。

## 設定

- `config.json` を編集してオプションを調整します。
  - 主要項目:
    - `submit_mode`: `"json"` または `"form"`
    - `api_post_url`: JSON 直POST の送信先（例: `https://bunko.ozeu.site/api/bunko`）
    - `threads`, `total_submissions`, `min_delay_ms`, `max_delay_ms`
    - `proxies`: プロキシの配列（HTTP/HTTPS または SOCKS4/5）
      - 例（HTTP/HTTPS）:
        ```json
        {"type": "http", "http": "http://<http-proxy-host>:<port>", "https": "http://<http-proxy-host>:<port>"}
        ```
      - 例（SOCKS5 認証付き）:
        ```json
        {"type": "socks5", "host": "<socks-host>", "port": 1080, "username": "<user>", "password": "<pass>"}
        ```
    - `form`: 各フィールドのテンプレート
      - `${random_string:min,max}` と `${bug_text:light|medium|heavy}` が使用可能
    - `headers`: 追加ヘッダー（必要に応じて Origin/Referer 等）

## フィールドを自分で変えれば別のサイトでも自動送信ができます