# Статус мимикрии: что уже совпадает байт-в-байт, а что нет

**Дата: 2026-09-02. Проверено живьём на стенде `test.auto-gram.ru`.**

Как проверяем: реальный браузер (Windows 11 Chrome 152 headed, Android 10
Chrome 152, Safari на macOS) заходит на `https://test.auto-gram.ru/fp` —
стенд отдаёт полный фингерпринт посетителя: сырое TLS-приветствие
(JA3/JA4/JA4_r/hex), расшифрованные h2-кадры (SETTINGS, порядок
заголовков), HTTP-заголовки, IP TTL и TCP-опции SYN. Затем тот же стенд
посещает наш клиент (site-mimic), и отчёты сравниваются в одном месте
(`/fp/recent` — последние 50 отчётов). h2-кадры дополнительно
расшифрованы из pcaps по TLS-keylog.

## Что уже совпадает с реальным Chrome — байт-в-байт

| Уровень | Реальный Chrome 152 (Windows, headed) | site-mimic (chrome_exact) | Статус |
|---|---|---|---|
| h2 SETTINGS | `1=65536, 2=0, 4=6291456, 6=262144` | то же | ✅ совпадает |
| h2 WINDOW_UPDATE (conn) | `inc=15663105` | `inc=15663105` | ✅ совпадает |
| h2 порядок заголовков | `:method,:authority,:scheme,:path` + sec-ch-ua → sec-ch-ua-mobile → sec-ch-ua-platform → upgrade-insecure-requests → user-agent → accept → sec-fetch-site → sec-fetch-mode → sec-fetch-user → sec-fetch-dest → accept-encoding → accept-language → priority | то же (13=13) | ✅ совпадает |
| HTTP-заголовки, множество имён | 13 | 13 | ✅ совпадает |
| IP TTL | 128 (на Windows), в hairpin-логе 127 | `ip_ttl: 128` → 127 | ✅ ставится из профиля |
| TCP-опции SYN (множество) | `mss 1460, wscale 8, sackOK` (без TS) | `mss 1460, sackOK, wscale 8` (без TS, sysctl-пресет хоста) | ✅ множество совпадает |
| Cookies / заголовки навигации | — | cookie-jar replay в клиенте | ✅ |

## Что разъехалось за сутки — главный урок

**ClientHello Chrome — не константа, а серверный эксперимент.**
2026-09-01 реальный Chrome 152 (Windows headed и «телефон» через
PCAPdroid-MITM) давал 18-расширенный набор с post-quantum-подписями и
`pre_shared_key`+`0xCA34`: JA4 `t13d1518h2_8daaf6152771_e2d80978ab2e`.
2026-09-02 тот же Chrome на тех же машинах даёт **17 расширений**,
`JA4 t13d1517h2_8daaf6152771_cb7bf5808d99` — одинаковый на Linux,
Windows и Android. Google выключил Finch-флаг за ночь. Вывод: эталоны
нужно снимать со стенда автоматически и регулярно, «вчерашний» JA4 не
обязан быть «завтрашним».

Следствия, зафиксированные сегодня:

- `chrome_exact` (транспорт, делегирующий bundled Chromium) отстал:
  его Chromium — 151, на проводе `t13d1516h2_…806a8c22fdea` против
  реального `cb7bf5808d99`. Нужно обновить bundled-браузер — и TLS
  снова байт-в-байт.
- uTLS-спека `chrome_152` собрана под вчерашний 18-расширенный
  эксперимент и сегодня устарела; актуальный эталон — 17 расширений.
- Строка матрицы «Android 152 = 18 расширений» была артефактом
  PCAPdroid-MITM (аддон сам перешифровывает TLS своим клиентом).
  Реальный end-to-end телефонный Chrome 152 = десктопный набор.

## Что пока НЕ мимикрим (честный список)

1. **TCP SYN, per-connection**: порядок TCP-опций и наличие
   timestamps задаются глобальным sysctl хоста, а не профилем.
   Видно на стенде: Windows шлёт `mss,wscale,sackOK`, наш Linux —
   `mss,sackOK,wscale`. Множество то же, порядок — Linux. Лечится
   отдельным netns с raw-SYN (или eBPF) на профиль.
2. **QUIC/HTTP3**: есть прототип (uQUIC, Chrome-115 пресет, наш JA4
   `q13d0310h3_…` проверен на проводе). До «идеала»: 152-exact QUIC
   пресет + поведение Alt-Svc/h3-fallback.
3. **TLS session resumption**: Chrome возвращает session tickets и
   сокращает рукопожатия; наш клиент делает полный handshake каждый
   раз. Антибот видит «все соединения — новые».
4. **ECH**: реальный Chrome отправляет Encrypted Client Hello GREASE;
   поведение нашего стека — не разобрано до конца.
5. **IP ID / DF / TOS паттерны** и прочие мелочи L3 — фиксируются
   стендом, но пока не подменяются per-profile.
6. **Поведенческий слой**: тайминги, порядок загрузки ресурсов, кэш,
   referer-цепочки — не мимикрируются транспортом (отдельная работа).
7. **Пользовательские поля**: `accept-language` и т.п. — сейчас
   зашиты; надо параметризовать под целевого юзера.

## План (по порядку)

1. Обновить bundled Chromium в `chrome_exact` до 152+ → TLS снова
   байт-в-байт (быстрый выигрыш).
2. Пересобрать uTLS-спеку `chrome_152` под актуальный 17-расширенный
   набор; автоматический «canary»: раз в сутки реальный браузер и наш
   клиент ходят на стенд, diff JA4/заголовков/TTL публикуется.
3. Per-connection TCP SYN (netns + raw) — порядок опций и TS.
4. QUIC 152-exact пресет (uQUIC `QUICSpec`) + h3.
5. Session resumption (переиспользование tickets).
6. Параметризация пользовательских полей (accept-language и пр.).

Инструменты, которыми всё это снято (в этом репозитории):
`cmd/fpd` — стенд-«эхо» полного фингерпринта (`/fp`, `/fp/recent`),
`tools/ja4_from_pcap.py`, `tools/ja3_ja4.py` (FoxIO JA4),
`mimic/` — клиенты (chrome_exact / chrome_152 / android_149, WithTTL),
keylog + ручная расшифровка TLS1.3 для h2-кадров.
