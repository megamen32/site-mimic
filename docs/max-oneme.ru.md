# MAX (ru.oneme.app) и web.max.ru: профили приложения и веба

Дата замеров: 2026-10-19, Samsung SM-G998B (Android 15, root), приложение
MAX 26.35.1 (`ru.oneme.app`) и мобильный Chrome 155 на том же телефоне.
Захват: `nat REDIRECT` → `tproxyfwd` → SOCKS5 → `mitmdump --mode socks5`
(подробно — `tools/phone/README.md`).

## Короткий ответ

**Приложение MAX — не браузер, и профиль браузера для него не подходит.**
Его TLS-стек — системный провайдер Android (Conscrypt) через OkHttp, и у
этого стека есть три признака, которых нет ни у одного браузера:

1. **Нет расширения ALPN вообще.** Приложение не предлагает ни `h2`, ни
   `http/1.1` — значит, HTTP/2 невозможен, соединение всегда HTTP/1.1.
2. **17 шифров, включая CBC-SHA1** (`0xc009/0xc00a/0xc013/0xc014`) и
   `status_request` (`0x0005`) — расширение, которое браузеры не шлют.
3. **Подпись без постквантовой ветки**: `rsa_pss_pss_*` отсутствует.

**Веб-версия — обычный Chrome 155**, и её JA4 совпадает с уже
имеющейся в репозитории спекой `chrome_152`: `t13d1517h2_8daaf6152771_cb7bf5808d99`.
Новой TLS-спеки для веба не нужно — нужны только заголовки.

## Приложение: числа

| Характеристика | MAX 26.35.1 → `api2.oneme.ru` | mimic (`max_app`) |
|---|---|---|
| JA3 | `771-4865,4866,4867,49195,49196,52393,49199,49200,52392,49161,49162,49171,49172,156,157,47,53-0,23,65281,10,11,35,5,13,51,45,43-29,23,24-0` | **то же** |
| JA3 md5 | `fb1972c15d60b7be0427edfbd00affde` | **то же** |
| JA4 | `t13d171100_5b57614c22b0_40271e0a5736` (11 расширений) | **то же** |
| JA4 (вариант с PSK) | `t13d171200_5b57614c22b0_352634941f3a` (12 расширений) | **то же** |
| ALPN | отсутствует | **отсутствует** |
| Шифров | 17 | 17 |
| Расширений | 11 (+`0x0029` при resumption) | 11 (+`0x0029`) |
| session id | 32 байта | 32 байта |
| ALPN-версия HTTP | HTTP/1.1 | HTTP/1.1 (h2 не предлагается) |

Порядок расширений приложения (Conscrypt не перемешивает):

```
0x0000 server_name          0x0023 session_ticket     0x002d psk_key_exchange_modes
0x0017 extended_master_secret 0x0005 status_request  0x002b supported_versions
0xff01 renegotiation_info   0x000d signature_algorithms 0x0033 key_share
0x000a supported_groups     0x000b ec_point_formats
```

Группы `29,23,24` (X25519, P-256, P-384), point formats `[0]`, версии
`772,771` (TLS 1.3, 1.2), sigalgs
`1027,2052,1025,1283,2053,1281,2054,1537,513`.

**Resumption преобладает.** Из 116 соединений к `api2.oneme.ru` 113 несли
`pre_shared_key` (`0x0029`, 267 байт) последним расширением, 3 были
чистыми full handshake. Поэтому в репозитории два профиля:

* `max_app` — 11 расширений, свежее соединение;
* `max_app_psk` — 12 расширений, dominant-shape (тот же, что у 113 из 116
  соединений приложения).

Фикстуры: `mimic/testdata/max_app_clienthello_full.json`,
`mimic/testdata/max_app_clienthello_psk.json`. Тест
`mimic/spec_max_app_test.go` — не сравнение структуры, а **настоящий
хендшейк uTLS**, разобранный тем же парсером, что и живой захват: JA3, JA4,
порядок шифров, порядок расширений, payload'ы детерминированных расширений
(включая `status_request`) и байты PSK должны совпасть с эталоном.

## Приложение: заголовки

`i.oneme.ru` (CDN) — единственный хост, чьи запросы mitmproxy смог
разобрать как HTTP:

```
Cache-Control: no-store
Accept: image/webp,/;q=0.8
User-Agent: OKMessages%2F26.35.1+%28Android+15%3B+samsung+SM-G998B%3B+450dpi+450dpi+1080x2400%29
Host: i.oneme.ru
Connection: Keep-Alive
Accept-Encoding: gzip
```

Две детали, важные для профиля:

* **User-Agent приходит percent-encoded** — `OKMessages%2F26.35.1+%28…%29`.
  Это особенность OkHttp/приложения, а не артефакт захвата: в профиле
  стоит именно то значение, что ушло в сеть (`examples/profiles/max-app-oneme.json`).
* **Порядок заголовков нестандартный**: `Cache-Control` первым, `Host` — четвёртым.
  Профиль включает `http1_wire_order: true` и `wire_header_order`, поэтому
  блок пишется вручную. Единственное отклонение: транспорт всегда пишет
  `host` первым (так же, как undici), а приложение — четвёртым.

## Приложение: эндпоинты

| Хост | Что это |
|---|---|
| `api2.oneme.ru` | основной API приложения (116 соединений в захвате) |
| `i.oneme.ru` | CDN картинок/медиа (`/i?r=…&fn=sqr_192`) |

Запросы к `api2.oneme.ru` **не разбираются как HTTP**: mitmproxy не
извлёк ни одной строки запроса из 116 соединений, хотя TLS-хендшейки шли
нормально. Значит, поверх TLS приложение говорит своим бинарным протоколом,
а не HTTP/1.1. Это важно: профиль приложения воспроизводит транспорт и
заголовки CDN-запросов, но не «API-запрос MAX» — у него нет HTTP-формы.

Сторонние SDK внутри приложения (для полноты, они не часть профиля):
`stats-dg.rustore.ru` (UA `Dalvik/2.1.0 (Linux; U; Android 15; SM-G998B …)`),
`tracker-api.vk-analytics.ru` и `sdk-api.apptracer.ru` (UA `okhttp/4.12.0`).

## Веб: `web.max.ru`

Chrome 155 на телефоне, ALPN `h2,http/1.1`, 16 шифров, 19 расширений
(17 без GREASE). Chrome перемешивает порядок расширений на каждом
соединении, поэтому JA3 меняется (19 разных значений в 19 соединениях), а
JA4 стабилен:

```
t13d1517h2_8daaf6152771_cb7bf5808d99   (12 соединений — вариант с 0xCA34)
t13d1516h2_8daaf6152771_806a8c22fdea   (7 соединений — без 0xCA34)
```

Первый — ровно то значение, на котором построена спека `chrome_152` в
репозитории. То есть для веб-версии MAX профиль TLS не нужен: хватит
`tls_client_hello: "chrome_152"` и заголовков.

Заголовки сняты через **CDP**, а не через MITM: Chrome 155 (Chrome Root
Store) не доверяет ни системному CA (conscrypt APEX), ни user-store CA, ни
`--ignore-certificate-requests`; TLS-хендшейк с прокси падает с
`tls alert certificate unknown`. DevTools-протокол отдаёт заголовки без
CA вообще.

```
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/155.0.0.0 Mobile Safari/537.36
sec-ch-ua: "Google Chrome";v="155", "Chromium";v="155", "Not(A:Brand";v="24"
sec-ch-ua-mobile: ?1
sec-ch-ua-platform: "Android"
```

Ограничение CDP: `requestWillBeSent` отдаёт только заголовки, добавленные
браузером. `Host`, `Accept`, `Accept-Encoding`, `Accept-Language`, `Sec-Fetch-*`
и `Priority` добавляет сетевой стек — их в CDP нет, они взяты из
навигации в реальном браузере (как в `examples/profiles/android-chrome152.json`).

## Как пользоваться

```go
p := mimic.MustLoadProfile("examples/profiles/max-app-oneme.json")
c, _ := mimic.New(p)
req, _ := p.Request("GET", "https://i.oneme.ru/i?fn=sqr_192", nil)
resp, _ := c.Do(req)
```

Профиль приложения: `examples/profiles/max-app-oneme.json`
(`max_app_psk` + `http1_wire_order`). Профиль веба:
`examples/profiles/max-web-chrome155.json` (`chrome_152` + заголовки Chrome).

## Границы

* `api2.oneme.ru` — бинарный протокол поверх TLS, HTTP-профилем не
  воспроизводится (см. выше).
* PSK-payload в `max_app_psk` — это стёртый билет из живого захвата;
  сервер считает его неизвестным и отвечает full handshake, как и браузер
  со вчерашним билетом. JA3/JA4 payload не хешируют, поэтому на
  отпечаток это не влияет.
* Позиция `Host` в HTTP/1.1-блоке приложения отличается (см. выше).
* `Accept-Encoding` приложения — `gzip` (не `gzip, deflate, br`): wire-транспорт
  сам распаковывает gzip, а Go не умеет Brotli.
