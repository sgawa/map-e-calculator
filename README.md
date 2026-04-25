# MAP-E計算機

`v6プラス`、`BIGLOBE IPv6オプション`、`OCNバーチャルコネクト` を対象としたMAP-E計算用のWEBアプリです。

## MAP-E

MAP-E は、IPv4 パケットを IPv6 網でカプセル化して運び、複数利用者で 1 つの IPv4 アドレスを共有する方式です。  
共有の識別には IPv4 アドレスだけでなく `Port Set` も利用します。

この計算機では、MAP-E の基本的なルールとして次の情報を使います。

- Rule IPv6 prefix
- Rule IPv6 prefix length
- Rule IPv4 prefix
- Rule IPv4 prefix length
- EA bit length
- PSID offset
- BR IPv6 address

入力として受け取るのは、利用者側に割り当てられた IPv6 プレフィックス、またはその範囲内の IPv6 アドレスです。  
計算は大まかに次の流れで行います。

1. IPv6 入力を正規化する
   圧縮表記、完全表記、CIDR 付き表記を受け付けます。

2. サービスごとの Rule IPv6 prefix と照合する
   入力 IPv6 がどの MAP-E ルールに属するかを判定します。

3. EA bits を取り出す
   Rule IPv6 prefix の直後にある EA bits を取り出します。

4. EA bits を IPv4 suffix と PSID に分解する
   計算には次の関係を利用します。

   - `p = 32 - ruleIpv4PrefixLength`
   - `psidLength = eaLength - p`

   ここで、

   - `p` は IPv4 suffix の長さ
   - `psidLength` は PSID の長さ

   となります。

5. 共有 IPv4 アドレスを求める
   Rule IPv4 prefix に IPv4 suffix を合成して、利用者の共有 IPv4 アドレスを求めます。

6. PSID を求める
   EA bits の下位側から PSID を取り出します。

7. 利用可能ポート範囲を求める
   `PSID offset`、`PSID length`、`PSID` を使って、その利用者に割り当てられるポート集合を列挙します。

## 出力項目

- `IPv4 アドレス`
  利用者に割り当てられた共有 IPv4 グローバルアドレス
- `PSID`
  共有 IPv4 上でその利用者を識別する Port Set ID
- `利用可能ポート範囲`
  その PSID に割り当てられたポート集合
- `CE アドレス`
  CE 側で利用される IPv6 アドレス表示
- `BR アドレス`
  収容先 BR の IPv6 アドレス
