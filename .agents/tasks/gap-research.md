# Gap-research на живом стенде (2026-09-02)

- **Wanted**: полное сравнение real-браузеров vs нашей мимикрии на одном приёмнике + shareable gap-документ.
- **Canary**: /fp/recent содержит отчёты реальных Chrome (Windows headed, телефон e2e) и наших профилей; diff задокументирован.
- **Result**: docs/RESEARCH-STATUS.ru.md.

Findings: Finch-эксперимент (18-ext e2d80978ab2e) выключен Google за ночь → все Chrome 152 = 17-ext cb7bf5808d99; PCAPdroid-MITM артефакт в матрице (телефон); bundled Chromium в chrome_exact = 151 (отстал); priority header отсутствовал в профилях (добавлен, проверено на стенде); h2 SETTINGS/WU/pseudo-header order у chrome_exact == реальный Chrome байт-в-байт.

Status: DONE (документ + матрица + профили закоммичены)
