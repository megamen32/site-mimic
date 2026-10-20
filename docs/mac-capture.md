# Захват с Mac: ClientHello и заголовки настоящего Chrome

Дата замеров: 2026-10-20, macOS 26.7.2 (25G325), Apple Silicon, Chrome
155.0.8059.85, страница `https://example.com/`.
Захват: `tools/mac/capture.sh` — отдельный экземпляр Chrome с
собственным `--user-data-dir`, явный прокси mitmproxy на 127.0.0.1 и
DevTools-протокол для заголовков (подробно — `tools/mac/README.md`).

## Короткий ответ

**Mac даёт полноценный десктопный захват без root, без телефона и без
установки CA в системное хранилище.** Тот же ClientHello, что и у
референсного десктопного Chrome, воспроизводится побайтно: JA4
`t13d1517h2_8daaf6152771_cb7bf5808d99` — ровно то значение, которое уже
зафиксировано в репозитории для `chrome_exact` (`docs/phone-reference.md`).
Новой TLS-спеки для десктопного Chrome не нужно — нужны заголовки, и они
теперь снимаются на той машине, на которой вы работаете.

| Что | Как снято | Где в файле |
| --- | --- | --- |
| ClientHello | прокси читает байты до показа сертификата | `kind: "hello"`, `source: "mitm"` |
| Полный набор заголовков на проводе | то, что ушло в туннель | `kind: "http"`, `source: "mitm"` |
| Заголовки, которые добавляет сам браузер | DevTools-протокол | `kind: "request"`, `source: "cdp"` |

## Цепочка

```
Chrome (свой --user-data-dir) ──CONNECT──▶ mitmproxy 127.0.0.1:18080
        │                                      │
        │ CDP (--remote-debugging-port)        │ mitm_capture_addon.py
        ▼                                      ▼
   cdp_headers.py ───────────────────▶ capture.jsonl (hello + заголовки)
```

Две ноги, потому что одной не хватает: CDP отдаёт только те заголовки,
которые добавляет браузер, — `Host`, `Accept`, `Accept-Encoding`,
`Accept-Language`, `Connection` и квартет `sec-fetch-*` добавляет сетевой
стек, и в `requestWillBeSent` их нет. Прокси-нога их видит, поэтому в
файл попадают обе, а каждая запись помечена `source`.

## Числа

Один прогон, `https://example.com/`, Chrome 155 на macOS:

```
SNI      example.com
ALPN     h2,http/1.1
version  771
ciphers  16 [6682 4865 4866 4867 49195 49199 49196 49200 52393 52392 49171 49172 156 157 47 53]
exts     [43690 0 35 10 51764 45 51 11 5 16 13 18 43 27 65037 17613 65281 23 6682]
groups   [23130 4588 29 23 24]
sigalgs  [2570 2308 2309 2310 1027 2052 1025 1283 2053 1281 2054 1537]
sid_len  32
JA3_MD5  bf1442c578c36293c2e84fc63a564c9a
JA4      t13d1517h2_8daaf6152771_cb7bf5808d99
```

* 19 расширений в hello, из них два — GREASE (`0xAAFA`, `0x1A1A`), поэтому
  JA4 считает 17 — как и зафиксировано для десктопного Chrome 152+;
* `0xCA24` (51764) на месте, постквантовые `0x0904/0x0905/0x0906` в
  `signature_algorithms` — то есть это тот же класс, что и в
  `docs/phone-reference.md`;
* группы: X25519MLKEM768 (`0x11EC`), X25519, P-256, P-384;
* **JA3 гуляет от соединения к соединению, JA4 — нет.** Четыре
  независимых прогона подряд дали разные JA3 md5
  (`bf1442c5…`, `faa1f529…`, `9aa33453…`, `6df67fb2…`) и один и тот же
  JA4 `t13d1517h2_8daaf6152771_cb7bf5808d99`. Это поведение браузера
  (перемешивание расширений и GREASE), а не инструмента.

## Заголовки

То, что реально ушло на провод (нога mitmproxy, `kind: "http"`):

```text
sec-ch-ua: "Google Chrome";v="155", "Chromium";v="155", "Not(A:Brand";v="24"
sec-ch-ua-mobile: ?0
sec-ch-ua-platform: "macOS"
upgrade-insecure-requests: 1
user-agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/155.0.0.0 Safari/537.36
accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/jxl,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
sec-fetch-site: none
sec-fetch-mode: navigate
sec-fetch-user: ?1
sec-fetch-dest: document
accept-encoding: gzip, deflate, br, zstd
accept-language: ru-RU,ru;q=0.9,en-US;q=0.8,en;q=0.7
priority: u=0, i
```

Что важно понимать:

* **`host` в списке заголовков нет.** mitmproxy выносит его в
  `flow.request.host`, поэтому аддон пишет `host` и `path` отдельными
  полями записи, а не строкой заголовка;
* **`connection` нет** — соединение идёт по HTTP/2;
* **UA не выдаёт настоящую версию macOS.** Chrome замораживает её как
  `Macintosh; Intel Mac OS X 10_15_7` — так же, как и на других Маках;
* **`accept-language` зависит от языка системы** (`ru-RU` здесь), а
  `sec-ch-ua` перемешивается по запросам — это уже видно из двух
  прогонов подряд.

Заголовки в ноге CDP (`kind: "request"`) — только добавленные браузером:
`Upgrade-Insecure-Requests`, `User-Agent`, `sec-ch-ua`,
`sec-ch-ua-mobile`, `sec-ch-ua-platform`. Остальное — в ноге mitmproxy.

## Что Mac НЕ может снять

Честный список, без оговорок «примерно так»:

1. **ClientHello мобильного приложения.** TLS-стек Android (Conscrypt +
   OkHttp) у MAX, VK и прочих приложений отличается от браузерного: у
   MAX, например, вообще нет ALPN и 17 шифров. Маку это не под силу —
   для этого нужен реальный телефон (`docs/max-oneme.ru.md`).
2. **Приложение, а не браузер.** Захват снимает браузер целиком; apk с
   пропатченным сертификатом (`tools/phone/build_patched_apk.sh`) —
   только телефонный путь.
3. **QUIC-hello.** Скрипт запускает Chrome с `--disable-quic`, поэтому
   берётся TCP-hello. QUIC-Initial (`q13d…`) снимается на телефоне
   отдельно, через `tools/quic_initial.py`.
4. **Мобильные особенности сети** — перехват DNS на офисном роутере,
   HTTP/3 по умолчанию, реальный мобильный канал: это свойства телефона,
   не машины.
5. **Заголовки *вашего* Chrome с вашими расширениями.** Захват идёт на
   чистом профиле, поэтому это стоковые заголовки браузера, а не
   персонализированные. Расширения меняют набор client hints — если нужны
   именно «ваши», снимайте свой обычный Chrome через DevTools вручную.
6. **Сертификат, которому браузер доверяет.** CA mitmproxy нигде не
   ставится: в системном хранилище, в связке ключей и в профиле Chrome
   его нет. Браузеру на время запуска сказано игнорировать ошибки
   сертификата (`--ignore-certificate-errors` плюс
   `Security.setIgnoreCertificateErrors` по CDP), и для ClientHello это
   вообще не важно — байты читаются до показа сертификата.

## Как это соотносится с другими путями

| Путь | Что меряет | Что нужно | Досье |
| --- | --- | --- | --- |
| Телефон (`tools/phone/`) | приложение и мобильный браузер | рут, телефон, аренда | `docs/max-oneme.ru.md`, `docs/phone-reference.md` |
| Эмулятор (`tools/avd/`) | приложение в чистой среде | SDK, образ | `tools/avd/README.md` |
| Windows (`tools/win/`) | десктопный Windows как LAN-эталон | сеть, приёмник | `docs/phone-reference.md` |
| **Mac (`tools/mac/`)** | **десктопный Chrome, локально** | **ничего, кроме Chrome** | **этот файл** |

Путь для Mac — не замена телефону: это «быстрый честный десктопный
захват» на рабочей машине. Он закрывает задачу «снять настоящий браузер
сейчас», а задачу «снять мобильное приложение» по-прежнему закрывает
только телефон.

## Воспроизвести

```sh
tools/mac/capture.sh https://example.com/ --out /tmp/cap.jsonl
go run ./cmd/hellofp /tmp/cap.jsonl
```

Первый запуск создаёт virtualenv с mitmproxy
(`~/.local/share/site-mimic/venv`) — без sudo и без системной установки.
Пустой захват, «порт занят» и прочие сбои разобраны в
`tools/mac/README.md`.

## Гарантии и уборка

* **Профиль пользователя не трогается.** Захват идёт в отдельном
  экземпляре Chrome со своим `--user-data-dir` во временном каталоге;
  чужой Chrome не сигналится никогда — процессы убиваются по PID, а не по
  шаблону имени.
* **Связка ключей не трогается.** Chrome запускается с
  `--use-mock-keychain` и `--password-store=basic`.
* **Системный прокси не трогается.** Прокси — это флаг `--proxy-server`
  в одном запуске; `scutil --proxy` и `networksetup -getwebproxy` после
  прогона те же, что были до него.
* **За собой ничего не оставляет.** Свой экземпляр Chrome и свой
  mitmproxy убиваются по PID, временный каталог с профилем и логами
  удаляется по точному пути.

Проверено на этой машине: во время захвата набор изменившихся файлов в
`~/Library/Application Support/Google/Chrome` оказался **подмножеством**
того, что меняется в окне без всякого захвата (работающий браузер сам
пишет куки и фавиконы) —capture не добавил ни одного файла, а его Chrome
не держал открытыми **ни одного** файла в этом каталоге.
