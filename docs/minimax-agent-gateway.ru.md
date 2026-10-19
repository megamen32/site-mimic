# MiniMax: managed-шлюз против публичного Anthropic-эндпоинта

Дата замеров: 2026-10-19, macOS arm64, MiniMax Code 3.1.4 (Electron 42.8.0,
Node 24.18.0), стенд `test.auto-gram.ru` (fpd).

Вопрос, который закрывает этот документ: **чем отличается «просто curl к
Anthropic-эндпоинту MiniMax» от запроса через приложение MiniMax Code** —
и как собрать профиль `site-mimic`, который повторяет запрос приложения
один в один.

## Короткий ответ

Разница не в заголовках и не в TLS. Разница в трёх вещах:

1. **Разные продукты и разные адреса.** Приложение ходит не в публичный
   Anthropic-эндпоинт, а в управляемый шлюз подписки:
   `https://agent.minimax.io/mavis/api/v1/llm/v1/messages`.
   Публичный `https://api.minimax.io/anthropic/v1/messages` — это отдельный
   продукт с биллингом по API-ключу платформы; модели M Plan (например
   `MiniMax-M3.1-Flash-Preview`) там недоступны.
2. **Разные учётные данные.** Приложение авторизуется управляемым токеном
   `mmoat_…` (`clientId: mcode-public`, `audience: agent-backend`,
   `scope: agent.default`) в заголовке `Authorization: Bearer`. API-ключ
   платформы к шлюзу не подходит, а управляемый токен — не подходит к
   публичному эндпоинту.
3. **Разная сетевая личность.** Приложение — это Node/undici: ClientHello
   BoringSSL, ALPN только `http/1.1`, HTTP/1.1. `curl` на macOS — другой
   стек TLS и HTTP/2.

Заголовки, наоборот, **не являются** условием доступа: запрос с одним
только `Authorization: Bearer <managed-токен>` и `content-type` получает
`200 OK`. Шлюз смотрит на учётные данные и на маршрут, а не на набор
заголовков.

## Живые замеры

Все запросы — с управляемым токеном из локального состояния входа MiniMax
Code (`~/.minimax/auth/prod/en/mcode-public/auth.json`).

| # | Запрос | Результат |
|---|---|---|
| 1 | curl, только `Authorization` + `content-type`, путь `…/llm/v1/v1/messages` | `401 {"code":401,"message":"auth failed"}` |
| 2 | curl, полный набор заголовков приложения, путь `…/llm/v1/v1/messages` | `401 {"code":401,"message":"auth failed"}` |
| 3 | curl, путь `…/llm/v1/messages` | `200 OK` + ответ модели |
| 4 | curl с **другим** токеном (JWT рантайма вместо `mmoat_…`) | `503 {"errorCode":50115,"errorReason":"direct_route_not_configured"}` |
| 5 | mimic-клиент с профилем ниже | `200 OK`, HTTP/1.1, ответ модели |

Пункты 1–2 важны: лишний `/v1` в пути ломает маршрут, а не заголовки.
Пункт 4: подмена токена даёт «маршрут не настроен», а не 401 — шлюз не
узнаёт учётные данные.

## Транспорт: curl против приложения

Замер сделан на стенде `https://test.auto-gram.ru/fp` — он показывает то,
что видит сервер.

| Характеристика | curl 8.7.1 (macOS) | MiniMax Code (Node 24 / undici) | mimic (`node_24`) |
|---|---|---|---|
| JA3 | `771-4865,…,156,157,47,53-0,23,65281,10,11,35,16,13,51,45,43,21-29,23,24-0` | то же | **то же, байт-в-байт** |
| JA4 | `t13d4907h2_0d8feac7bc37_7395dae3b2f3` | `t13d1812h1_5d04281c6031_ef7df7f74e48` | **`t13d1812h1_5d04281c6031_ef7df7f74e48`** |
| ALPN | `h2, http/1.1` → `h2` | `http/1.1` | `http/1.1` |
| HTTP | 2.0 | 1.1 | 1.1 |
| Шифры | 16 | 18 | 18 |
| Расширения | 17 | 12 | 12 |
| Session ID | 32 байта | 32 байта | 32 байта |
| Padding | Chrome (0x0015) | BoringSSL: hello дополняется до 512 байт | то же |

## Заголовки и тело: что реально уходит от приложения

Снято побайтно (клиент приложения → локальный сток, TLS завершается на
стороне стока):

```
POST /v1/messages HTTP/1.1
host: 127.0.0.1:18991
connection: keep-alive
X-Stainless-Timeout: 600
X-Stainless-Package-Version: 0.91.1
anthropic-version: 2023-06-01
accept: application/json
anthropic-dangerous-direct-browser-access: true
Authorization: Bearer mmoat_…
x-api-key: sk-xxx
x-mavis-session-id: mvs_…
x-mavis-agent-id: main
x-mavis-timezone-offset: 10800
user-agent: MiniMaxAgent
x-stainless-lang: js
x-stainless-os: MacOS
x-stainless-arch: arm64
x-stainless-runtime: node
x-stainless-runtime-version: v24.18.0
x-stainless-retry-count: 0
content-type: application/json
accept-language: *
sec-fetch-mode: cors
accept-encoding: gzip, deflate
content-length: 105

{"model":"MiniMax-M3.1-Flash","max_tokens":16,"messages":[{"role":"user","content":"hi"}],"stream":false}
```

Особенности, которые не видны в коде и которые профиль обязан повторить:

- `x-api-key: sk-xxx` — **заглушка**, а не ключ: управляемый режим кладёт
  в `x-api-key` константу `MANAGED_PROVIDER_API_KEY_PLACEHOLDER`, а настоящая
  авторизация едет в `Authorization: Bearer`.
- `User-Agent: MiniMaxAgent` — не `MiniMaxCode`: у управляемого маршрута своя
  идентичность (`withMiniMaxCodeUserAgent` применяется к сторонним
  провайдерам, а управляемый переписывает UA на `MiniMaxAgent`).
- Имена заголовков смешанного регистра: `X-Stainless-Timeout` и
  `X-Stainless-Package-Version` с большой буквы, `anthropic-version` и
  `content-type` — с маленькой. Это поведение undici: объектные заголовки
  сохраняют регистр, а заголовки из `Headers` lowercаются.
- Три заголовка `X-Mavis-*` — идентичность рантайма (сессия, агент, часовой
  пояс клиента).
- `accept-encoding: gzip, deflate` — undici не просит br.

## Что добавлено в `mimic`

1. **`tls_client_hello: "node_24"`** (`mimic/spec_node.go`) — ClientHello
   Node 24 / Electron: 18 шифров, 12 расширений в фиксированном порядке
   BoringSSL, 32-байтный session id, key share только x25519, ALPN
   `http/1.1`. JA3/JA4 совпадают с приложением байт-в-байт (проверено на
   стенде).
2. **Режим HTTP/1.1 без пробы h2.** Клиент, который предлагает только
   `http/1.1`, не может получить h2, поэтому транспорт не тратит второе
   рукопожатие на попытку.
3. **Точный порядок заголовков на проводе** (`mimic/http1.go`,
   `http1_wire_order` + `wire_header_order` в профиле). Go канонизирует и
   пересортировывает заголовки, а порядок — часть отпечатка; профиль пишет
   блок заголовков сам, сохраняя исходный регистр.
4. **Профиль и пример**: `examples/minimax-agent-gateway/`.

## Как пользоваться

```sh
cd examples/minimax-agent-gateway

# живой запрос управляемому шлюзу (токен берётся из локального состояния входа)
go run . -prompt "Reply with the single word: ok"

# свой токен
MINIMAX_MANAGED_TOKEN=mmoat_… go run .

# отпечаток транспорта: сравнить с приложением
go run . -fingerprint https://test.auto-gram.ru/fp

# raw ClientHello → JA3/JA4
go run . -dump ch.json
python3 ../../tools/parse_clienthello.py ch.json
```

Токен в профиле не хранится: `Authorization` ставится на запрос из
`MINIMAX_MANAGED_TOKEN` или из `~/.minimax/auth/prod/en/mcode-public/auth.json`.

## Проверка «один в один»

| Слой | Как проверяется | Итог |
|---|---|---|
| TLS | JA3/JA4 на стенде `test.auto-gram.ru/fp` | совпадают с приложением |
| ALPN / HTTP-версия | стенд | `http/1.1`, HTTP/1.1 |
| Порядок и регистр заголовков | побайтовое сравнение с локальным стоком | совпадают |
| Тело | побайтовое сравнение | совпадают (одинаковый `content-length`) |
| Бизнес-путь | реальный запрос к шлюзу | `200 OK`, ответ модели |

## Ограничения

- Профиль повторяет **этот** клиент на **этой** машине: `x-stainless-os:
  MacOS`, `x-stainless-arch: arm64`, `x-stainless-runtime-version: v24.18.0`
  — характеристики узла, а не клиента. На другом хосте их надо менять.
- Транспорт `http1_wire_order` не переиспользует соединение (один запрос —
  одно соединение) и не умеет chunked-тела запросов.
- Профиль повторяет managed-шлюз MiniMax. Публичный
  `api.minimax.io/anthropic` — другой продукт: там нужен API-ключ платформы
  и другие модели, профиль для него — другой.
- Поведение при 401/503 шлюз не меняет: ответ приходит как есть.
