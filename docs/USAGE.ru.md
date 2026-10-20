# Как пользоваться site-mimic

Это руководство для оператора: какие профили уже готовы, как пользоваться
site-mimic из Go и из Python и какие правила нужны, чтобы транспорт не
врёт. Методика (как подогнать *новый* сайт) живёт в
[`skill/SKILL.md`](../skill/SKILL.md) и
[`docs/methodology.md`](methodology.md); этот файл — про то, что уже есть.

## Три способа войти

| вы пишете на | используйте | что это |
| --- | --- | --- |
| Go | `mimic.New(profile, opts...)` | `*http.Client` с uTLS-транспортом, всё в процессе |
| Python | `site_mimic_client.gohttp` | клиент в форме `requests`, ходит в демон `fetchd` |
| ИИ-агент | [`skill/SKILL.md`](../skill/SKILL.md) | маршрут «захват → профиль → проверка» |

### Go

```go
profile := mimic.MustLoadProfile("profile.json")
client, err := mimic.New(profile, mimic.WithTTL(128))   // 128 = выглядим как Windows
resp, err := client.Get("https://example.com/")
```

`mimic.Profile` несёт всю идентичность: форму ClientHello, набор и порядок
заголовков, TTL исходящего IP и опциональный план ресурсов, который
превращает один запрос в браузерную сессию. Опции `mimic.New` — прокси,
пиннинг DNS, проверка TLS, таймаут соединения, подмена SNI.

### Python

В Python всё делает один модуль — `site_mimic_client.gohttp`, он говорит с
демоном `fetchd` по HTTP:

```sh
go build -o fetchd ./cmd/fetchd
./fetchd                     # слушает :30777, опционально FETCHD_TOKEN
```

```python
from site_mimic_client import gohttp

r = gohttp.get(
    "https://example.com/api/...",
    profile="/path/to/profile.json",
    headers={"Accept": "application/json"},
)
print(r.status, r.text)
```

Клиент сам следит за демоном: если `/healthz` недоступен, он один раз
поднимает `fetchd` и повторяет запрос. Настройка — через окружение:
`GOHTTPD_URL` (по умолчанию `http://127.0.0.1:30777`), `GOHTTPD_TOKEN`,
`GOHTTPD_BIN`, `GOHTTPD_LOG`.

## Готовые профили

### TLS-спеки ClientHello — значение поля `tls_client_hello`

| спека | кого имитирует | эталон на проводе (JA4) | примечания |
| --- | --- | --- | --- |
| `chrome_auto` (по умолчанию) | Chrome, автоопределение | `t13d1516h2_8daaf6152771_d8a2da3f94cd` | встроенная в uTLS |
| `android_149` | мобильный Chrome 149 (S21) | тот же | мобильный эталон |
| `chrome_152` | Chrome 152 на десктопе / 155 на телефоне | `t13d1517h2_8daaf6152771_cb7bf5808d99` | своя спека: постквантовые алгоритмы подписи + расширение 0xCA24 |
| `chrome_152_psk` | то же, но с resumption | — | добавляет PSK binder |
| `node_24` | Node.js 24 / Electron 42 (BoringSSL) | `t13d1812h1_5d04281c6031_ef7df7f74e48` | ALPN только `http/1.1` |
| `max_app` | приложение MAX (`ru.oneme.app`) | `t13d171100_5b57614c22b0_40271e0a5736` | форма Conscrypt/OkHttp, **ALPN нет вообще**, 17 шифров |
| `max_app_psk` | то же, с resumption | `t13d171200_5b57614c22b0_352634941f3a` | PSK несли 113 из 116 реальных соединений |
| `firefox_auto`, `ios_auto`, `random`, `random_alpn` | Firefox, iOS, случайный | — | встроенные в uTLS |
| `chrome_exact` | настоящий Chrome, байт в байт | `t13d1516h2_8daaf6152771_806a8c22fdea` | это не uTLS-спека: транспорт делегирован [headless-client](https://github.com/kulikov0/headless-client), который снят с актуального стабильного Chrome |

`max_app` — единственная спека **без ALPN**: она умеет только HTTP/1.1.
Профиль с ней обязан ставить `http1_wire_order` и `wire_header_order` —
это единственный путь, где порядок заголовков на проводе под нашим
контролем (см. «Известные ограничения»).

### JSON-профили — готовая личность, готовая к загрузке

| файл | имя | цель | TLS-спека | TTL |
| --- | --- | --- | --- | --- |
| `examples/profiles/android-chrome152.json` | `android-chrome152` | мобильный Chrome 152 | `chrome_152` | 64 |
| `examples/profiles/linux-chrome152.json` | `linux-chrome152` | десктопный Chrome 152 | `chrome_exact` | — |
| `examples/profiles/mac-chrome153.json` | `mac-chrome153` | Chrome 153 на macOS | `chrome_exact` | — |
| `examples/profiles/windows-chrome152.json` | `windows-chrome152` | Windows Chrome | `chrome_exact` | 128 |
| `examples/profiles/max-app-oneme.json` | `max-app-oneme-26.35.1` | приложение MAX 26.35.1 | `max_app_psk` | 64 |
| `examples/profiles/max-web-chrome155.json` | `max-web-chrome155` | `web.max.ru` в мобильном Chrome 155 | `chrome_152` | 64 |

В каждом файле — user agent, набор заголовков и его порядок, а там, где
было захвачено, — план ресурсов. Загрузка:
`mimic.MustLoadProfile("examples/profiles/windows-chrome152.json")`.

### Готовые примеры

| пример | что показывает |
| --- | --- |
| `examples/vk-ru` | десктопный Chrome против `vk.ru` |
| `examples/vk-ru-mobile` | тот же сайт как мобильный браузер |
| `examples/vk-ru-windows` | Windows-профиль, TTL 128 |
| `examples/stream-wb-ru` | cookie jar, собранный браузером, против 498-челленджа |
| `examples/stand-probe` | долгоживущий клиент, отдающий fingerprint-эндпоинт |
| `examples/lan-probe` | проба внутри netns с выбранным TCP-образом |
| `examples/minimax-agent-gateway` | транспорт, который использует агентный шлюз |
| `examples/uquic-probe` | эксперименты с QUIC и initial-пакетами |

## Как подогнать новый сайт

1. **Сними настоящего клиента.** Телефон, Windows-машина или эмулятор:
   [`tools/phone/README.md`](../tools/phone/README.md),
   [`tools/win/README.md`](../tools/win/README.md),
   [`tools/avd/README.md`](../tools/avd/README.md).
   Дешёвый путь, когда нужен только JA3/JA4, — `cmd/hello-tap`.
2. **Прочитай отпечатки** через `cmd/hellofp` (для захвата site-mimic) или
   `tools/ja4_from_pcap.py` (для pcap). Оба разбирают хендшейк кодом самой
   библиотеки — значит, числа те же, что посчитал бы сервер.
3. **Напиши спеку** в `mimic/spec_*.go` и положи рядом фикстуру — сырые
   байты ClientHello из захвата.
4. **Закрепи тестом**, который делает **настоящий** хендшейк и сверяет
   отпечаток. Тест, который сравнивает только структуру спеки, не поймает
   перепутанную константу uTLS — именно так однажды уцелела переставленная
   пара шифров.
5. **Опиши профиль** в `examples/profiles/` и заметки — в `docs/`.

Полная последовательность с обоснованием каждого шага — в
[`skill/SKILL.md`](../skill/SKILL.md).

## Правила, без которых работа превращается в выдумку

* **Одна истина для питон-клиента.** Канон — `python/site_mimic_client/gohttp.py`,
  а потребители ставят его как git-зависимость с закреплением на теге:
  файла-клона, который может разъехаться, там нет вообще. Правь здесь →
  подними версию → выложи тег → перепини. Никогда не правь установленную
  копию: следующая переустановка молча отменит правку.
* **Закрепляй по тегу, а не по ветке.** Зависимость потребителя:
  `site-mimic @ git+https://github.com/megamen32/site-mimic.git@<tag>#subdirectory=python`.
  Выпустил тег — перепини в lock-файле, чтобы было видно, что именно
  запущено.
* **Не заявляй отпечаток, который не измерил.** JA4 в README — это
  измерение; JA4, скопированный из другого проекта, — догадка. Перемеряй
  инструментами этого репозитория.
* **Не оставляй корень.** mitmproxy-CA не должен переживать захват: ни в
  системном хранилище телефона, ни в mount-namespace зygote, ни в
  пользовательском хранилище чужой Windows-машины, ни в твоём keychain.
  Инструменты сами размонтируют и удаляют его — пользуйся ими.
* **Общий телефон — общий телефон.** Перед работой с устройством бери
  lease и отпускай его, когда закончил. Два агента, делящие одни и те же
  правила iptables, дают пустой захват по причинам, не связанным с
  приложением.
* **Публичный репозиторий должен быть самодостаточным.** Никаких ссылок
  на внутренние пути, хосты и репозитории. Если что-то нужно — оно лежит
  здесь.

## Известные ограничения

* **Порядок заголовков в HTTP/2** — канонический порядок Go, а не
  браузерный. Поле `header_order` фиксирует *намерение*; на проводе
  порядок управляется только для HTTP/1.1-профилей (`http1_wire_order` +
  `wire_header_order`).
* **`chrome_exact` требует внешний headless-client**; чистые uTLS-спеки
  близки к настоящему Chrome, но не байт в байт.
* **TTL — подсказка, а не гарантия.** Он проставляется на соединение, но
  hairpin--hop или middlebox меняют то, что видит сервер. `128` — дефолт
  Windows, `64` — Linux/Android.
* **QUIC нет.** Транспорт — HTTP/1.1 и HTTP/2. Сайту, который говорит
  только по HTTP/3, нужен другой инструмент.
* **Профиль — это один клиент на одном сайте.** Набор заголовков браузера
  на одном origin не переносится на другой origin без правок.

## Карта репозитория

| путь | что внутри |
| --- | --- |
| `mimic/` | библиотека: транспорт, спеки, работа с профилями, фингерпринтинг |
| `mimic/spec_*.go` | спеки ClientHello; в `mimic/testdata/` — фикстуры захватов |
| `cmd/fetchd` | демон для не-Go потребителей |
| `cmd/hello-tap`, `cmd/hellofp` | инструменты захвата и подсчёта отпечатков |
| `cmd/tproxyfwd` | прозрачный форвардер на рутованном телефоне |
| `examples/profiles/` | готовые JSON-профили |
| `examples/` | разобранные примеры, по одному на сайт |
| `python/site_mimic_client/` | канонический питон-клиент |
| `tools/phone/`, `tools/win/`, `tools/avd/` | инструменты захвата под каждую платформу |
| `tools/parse_clienthello.py`, `tools/ja4_from_pcap.py` | разбор отпечатков |
| `docs/` | методика, исследовательские заметки, документация по сайтам |
| `skill/SKILL.md` | агентный маршрут подгонки нового сайта |
