# zai-start-gateway — Z.ai ZCode start-plan через wire-identity десктопа

Говорит с `zcode.z.ai/api/v1/zcode-plan/anthropic/v1/messages` так, как это
делает установленный ZCode desktop (Electron 42 / Node 24): тот же endpoint,
тот же класс креденшала (сессионный JWT из общего `~/.zcode/v2/credentials.json`),
тот же набор заголовков и та же wire-identity (`node_24` ClientHello, ALPN http/1.1).

Квота Start-плана доступна ТОЛЬКО через этот путь: PAT-токены билдят отдельный
weekly-бакет, а session JWT принимает только zcode-plan endpoint.

Захват эталона: MITM через штатный seam десктопа (setting.json
`httpProxy` + `httpProxyCaCertPath`), эталонные заголовки и тело —
`~/zai-fix/mitm/capture-keep.log`, `fullbody_*.json`.

Важно: `metadata.user_id.session_id` и заголовок `x-session-id` должны быть
СВЕЖИМИ на каждый диалог — повтор чужой сессии даёт 400 "parameter error".

Usage:
    go run .                            # один запрос, печатает SSE
    go run . -prompt "ping"
    go run . -body file.json            # дословное тело
    go run . -jwtfile token.txt         # готовый bearer jwt
