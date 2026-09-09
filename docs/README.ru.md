# site-mimic

[English](../README.md) · [中文](README.zh-CN.md) · [HANDOFF](../HANDOFF.md)

> Заставляет Go HTTP-клиент выглядеть на уровне транспорта как реальный
> браузер, которого ждёт сайт: TLS ClientHello (JA3/JA4), ALPN, HTTP/2 и
> захваченный набор заголовков. Стандартный Go-TLS однозначно отличим, и
> именно сигнатуры ClientHello первыми начинают резать DPI-коробки (ТСПУ
> глушит по ClientHello/ServerHello — тем же механизмом, которым когда-то
> зарезали snowflake).

site-mimic — это проверенный в бою uTLS-транспорт плюс методология,
делающая «подгон под браузер» воспроизводимой: скилл для ИИ-агентов,
проходящий новый сайт от захвата до проверенного запроса, тулы
захвата/верификации и два готовых примера.

## Проверено (30.08.2026, против vk.ru)

| Клиент | JA4 (стенд, закреплённый Chromium) | Результат |
|---|---|---|
| uTLS `chrome_auto` | `t13d1516h2_8daaf6152771_d8a2da3f94cd` | 200 OK по HTTP/2; почти-матч (набор расширений чуть отличается) |
| `chrome_exact` (TLS делегирован [headless-client](https://github.com/kulikov0/headless-client)) | `t13d1516h2_8daaf6152771_806a8c22fdea` | **JA4 байт-в-байт совпадает с браузером** |
| Реальный телефон (Samsung S21 Ultra, Android Chrome 149, 4G) | тот же класс отпечатка: TLS 1.3, 16 шифров с GREASE, ALPN h2, шафл порядка расширений на каждое соединение | подтверждает десктопный эталон |

Также проверено: `stream.wb.ru` отдаёт тот же 498-челлендж антибота `wbaas`,
что и свежему реальному браузеру — транспортный паритет корректен, JS-челлендж
— слой приложения (см. `examples/stream-wb-ru`).

## Кредиты: headless-client — более точный транспорт

**[kulikov0/headless-client](https://github.com/kulikov0/headless-client) на
транспортном слое лучше, и site-mimic строится поверх него.** Его ClientHello
снят руками с актуального стабильного Chrome (включая постквантовые
алгоритмы подписи), поэтому он совпадает с браузером байт-в-байт, тогда как
готовый профиль uTLS `chrome_auto` немного отстаёт. Его HTTP-часть дополнительно
закрывает порядок заголовков, фрейминг HTTP/2 SETTINGS и переиспользование
соединений, а его стенд (`stand/`) диффит ваш бинарник с реальным Chromium
на проводе — это тот самый цикл верификации, который мы теперь рекомендуем
везде.

Ценность site-mimic — слой вокруг транспорта: скилл «подгон под сайт» для
ИИ-агентов, тулы захват→профиль→проверка, профили сайтов и проработанные
примеры. `tls_client_hello: "chrome_exact"` делегирует TLS/HTTP2-слои
headless-client (MIT, спасибо), `chrome_auto` и прочие остаются как
чисто-uTLS фолбэки.

## Установка

```sh
go get github.com/megamen32/site-mimic/mimic
```

## Быстрый старт

```sh
git clone https://github.com/megamen32/site-mimic && cd site-mimic/examples/vk-ru
go run . -dump ch.json
python3 ../../tools/parse_clienthello.py ch.json   # JA3/JA4 нашего ClientHello
```

Ожидаемо: `status: 200 OK`, `proto: HTTP/2.0` (`server: kittenx`). Дальше —
подгон нового сайта по [skill/SKILL.md](../skill/SKILL.md).

## Узнать больше

- [Методология подгона сайта (скилл для ИИ)](../skill/SKILL.md)
- [Как устроено, ограничения, роадмап](methodology.md)
- [HANDOFF — проверенное состояние и остатки работ](../HANDOFF.md)
- [Пример vk.ru](../examples/vk-ru/) · [Пример stream.wb.ru](../examples/stream-wb-ru/) · [Пробник для стенда](../examples/stand-probe/)

## Честные ограничения

С `chrome_exact` TLS-слой байт-в-байт; с uTLS-профилями — почти-матч.
Значения и состав заголовков точны, порядок на проводе и фрейминг HTTP/2
SETTINGS — гошные; QUIC/DTLS не покрыты — подробности в
[methodology.md](methodology.md). JS-челленджи антиботов сознательно вне
скоупа.

Лицензия MIT. Не аффилировано с VK и Wildberries.
