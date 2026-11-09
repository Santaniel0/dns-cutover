# dns-cutover

Проверка перед сменой NS-серверов домена. `dnscutover` напрямую опрашивает каждый старый и каждый новый авторитативный сервер, сравнивает зону запись за записью и проверяет делегирование и DNSSEC. Ничего не меняет, ключи API провайдеров не нужны.

## Зачем

Типичный переезд DNS выглядит так: домен обслуживался DNS-серверами регистратора (reg.ru, Namecheap) или хостинга, и его переносят в Yandex Cloud DNS или Cloudflare. Записи у нового провайдера заводят импортом zone-файла, автосканом или руками, потом у регистратора меняют NS. Перед этим шагом почти никто не может проверить, что новая зона совпадает со старой: AXFR публичные серверы не отдают, а Cloudflare прямо пишет в [документации](https://developers.cloudflare.com/dns/zone-setups/reference/dns-quick-scan/), что его скан ищет записи по списку типовых имён и может пропустить, например, DKIM с нестандартным селектором.

Ломается обычно одно и то же, и ломается тихо:

- DKIM-селектор, SRV для autodiscover или TXT для верификации не перенесли, и почта начинает попадать в спам или клиенты перестают настраиваться;
- MX ведёт на другой хост, или почтовый хост оказался за HTTP-прокси Cloudflare (оранжевое облако), и входящая почта перестаёт доходить;
- при импорте в апекс новой зоны попали NS старого провайдера;
- у регистратора остался DS от старого провайдера, а новая зона не подписана или подписана другим ключом. После смены NS валидирующие резолверы отвечают SERVFAIL на весь домен.

Вручную это проверяют циклом `dig @old` / `dig @new` и сравнивают глазами. Мешает всё сразу: порядок записей в ответе, разные TTL, длинный DKIM-ключ, который провайдеры режут на строки по 255 байт в разных местах, серверы одного провайдера, отвечающие по-разному, пока один из них не догнал изменения.

`dnscutover check` делает эту проверку одной командой и в конце пишет `READY` или `NOT READY`. Код выхода можно использовать как условие перед сменой NS.

## Установка

Нужен Go 1.27.

```
go install github.com/Santaniel0/dns-cutover/cmd/dnscutover@latest
```

Или из исходников:

```
git clone https://github.com/Santaniel0/dns-cutover
cd dns-cutover
go build -o dnscutover ./cmd/dnscutover
```

## Пример на локальной лаборатории

В репозитории есть `dnslab`: он поднимает на 127.0.0.1 четыре фейковых авторитативных сервера. Это родительская зона `test.`, старый провайдер зоны `example.test` и два сервера нового провайдера. Зоны лежат в `testdata/lab`. В «новую» зону специально заложены ошибки, которые встречаются при реальных переездах.

```
go run ./cmd/dnslab
```

```
dnslab: scenario broken, zone example.test.
  parent  zone test.         127.0.0.1:5300
  old     ns1.olddns.test.   127.0.0.1:5301
  new     ns1.newdns.test.   127.0.0.1:5302
  new     ns2.newdns.test.   127.0.0.1:5303
```

Во втором терминале:

```
go run ./cmd/dnscutover check example.test \
  --parent 127.0.0.1:5300 \
  --old ns1.olddns.test=127.0.0.1:5301 \
  --new ns1.newdns.test=127.0.0.1:5302,ns2.newdns.test=127.0.0.1:5303 \
  --zone-file testdata/lab/export.zone \
  --names testdata/lab/names.txt
```

Вывод этого запуска:

```
zone       example.test.
old        ns1.olddns.test. 127.0.0.1:5301 (from --old)
new        ns1.newdns.test. 127.0.0.1:5302
           ns2.newdns.test. 127.0.0.1:5303
parent     127.0.0.1:5300 NS ns1.olddns.test., ns2.olddns.test. (TTL 172800), DS 29212/13/2 (TTL 86400)
inventory  12 names: 8 zone-file, 1 names-file, 3 probe (139 labels probed)
compared   86 questions, 15 RRsets, 6 identical; 546 queries in 4.58s

BLOCKERS (7)
  MISSING         _autodiscover._tcp.example.test. SRV
                  old  0 0 443 autodiscover.mailhost.test.
                  new  (none)
  MISSING         _dmarc.example.test. TXT  on ns2.newdns.test.
                  old  "v=DMARC1; p=quarantine; rua=mailto:dmarc@example.t...
                  new  (none)
  MISSING         mail._domainkey.example.test. TXT
                  old  "v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCB...
                  new  (none)
  DIFFERENT       api.example.test. A
                  old  192.0.2.30
                       192.0.2.31
                  new  192.0.2.30
  PROXIED-TARGET  mail.example.test. A
                  old  192.0.2.25
                  new  104.21.48.11
                  MX target of example.test.; clients connecting to proxy
                  addresses will not reach the server (the proxy only passes
                  HTTP/HTTPS)
  APEX-NS         example.test. NS
                  new  ns1.newdns.test.
                       ns1.olddns.test.
                       ns2.newdns.test.
                  the new zone still lists the old nameservers
                  ns1.olddns.test. at the apex; resolvers that take the zone's
                  own NS set will keep going back to the old provider
  DNSSEC          example.test. DS
                  old  29212 13 2 DF74CEA5E9F8F95056E8245A1FD23D7728BE6997...
                  the parent publishes DS but the new zone is unsigned;
                  validating resolvers will return SERVFAIL for the whole
                  domain. Remove the DS at the registrar and wait out its TTL
                  of 1d (86400s) before changing NS

WARNINGS (3)
  EXTRA           staging.example.test. A
                  old  (none)
                  new  10.0.0.5
  TTL             example.test. A
                  ttl  3600 on old, 300 on new
                  data 192.0.2.10
  SERIAL          example.test. SOA
                  new servers return different SOA serials
                  (ns1.newdns.test.=2026110902, ns2.newdns.test.=2026110901);
                  one of them has not caught up yet

INFO (4)
  PROXIED         www.example.test. CNAME
                  old  example.test.
                  new  104.21.48.10
                  answered with proxy addresses instead of the CNAME; HTTP(S)
                  goes through the proxy, other protocols do not reach the
                  target
  TIMING          example.test. A
                  largest TTL on the old servers is 1h (3600s): a record
                  changed during the move can be served stale that long after
                  the switch
  TIMING          example.test. NS
                  parent NS TTL is 2d (172800s): after the switch some
                  resolvers keep asking the old servers that long, so leave
                  the old zone unchanged until then
  TIMING          example.test. SOA
                  negative-caching TTL of the new zone is 5m (300s): a name
                  missing at the switch stays missing in caches that long
                  after it is added

RESULT: NOT READY (7 blockers, 3 warnings, 4 info)
```

Код выхода 1. Что здесь произошло:

- `mail._domainkey` нет в выгрузке `export.zone`: в лабе это запись, которую панель старого хостинга ведёт сама и не экспортирует. Её нашёл перебор типовых имён (`3 probe` в строке inventory). Сервер `billing` есть только в `names.txt`, и он тоже сравнивался, просто совпал.
- `_dmarc` есть на `ns1.newdns.test`, но нет на `ns2.newdns.test`. Это видно, потому что каждый новый сервер сравнивается отдельно. Предупреждение `SERIAL` объясняет причину: второй сервер ещё не получил свежую версию зоны.
- DKIM-ключ `selector1` в старой и новой зоне разбит на строки в разных местах. В отчёт он не попал: перед сравнением строки TXT склеиваются.
- `www` у нового провайдера проксируется, это нормальное изменение, поэтому только INFO. `mail` проксироваться не должен: это цель MX, отсюда блокер.
- У регистратора (родительская зона `test.`) висит DS старого ключа, а новая зона не подписана.

Второй сценарий, `go run ./cmd/dnslab -scenario fixed`, это та же зона после исправлений. DS у регистратора удалён, `staging` оставлен специально и принят через `--ignore`:

```
go run ./cmd/dnscutover check example.test \
  --parent 127.0.0.1:5300 \
  --old ns1.olddns.test=127.0.0.1:5301 \
  --new ns1.newdns.test=127.0.0.1:5302,ns2.newdns.test=127.0.0.1:5303 \
  --zone-file testdata/lab/export.zone \
  --names testdata/lab/names.txt \
  --ignore "staging A"
```

```
zone       example.test.
old        ns1.olddns.test. 127.0.0.1:5301 (from --old)
new        ns1.newdns.test. 127.0.0.1:5302
           ns2.newdns.test. 127.0.0.1:5303
parent     127.0.0.1:5300 NS ns1.olddns.test., ns2.olddns.test. (TTL 172800)
inventory  12 names: 8 zone-file, 1 names-file, 3 probe (139 labels probed)
compared   86 questions, 15 RRsets, 12 identical; 546 queries in 4.58s

INFO (4)
  PROXIED         www.example.test. CNAME
  ...
IGNORED (1)
  EXTRA           staging.example.test. A

RESULT: READY (0 blockers, 0 warnings, 4 info)
```

(Блок INFO здесь сокращён, он такой же, как выше.) Код выхода 0.

Почти всё время запуска уходит на ожидание: по умолчанию к одному серверу уходит не больше 50 запросов в секунду, а старому серверу в этом примере досталось больше двухсот.

## Использование на реальном домене

```
dnscutover check example.com \
  --new ns1.yandexcloud.net,ns2.yandexcloud.net \
  --zone-file example.com.zone \
  --names extra-names.txt
```

Без `--old` старые серверы берутся из текущего делегирования: инструмент находит серверы родительской зоны (для `example.com` это серверы `com.`) через системный резолвер и спрашивает у них NS и DS домена напрямую.

Как задавать серверы: список через запятую, каждый в виде `ns1.example.net`, `ns1.example.net:5353`, `192.0.2.1`, `192.0.2.1:5353` или `ns1.example.net=192.0.2.1`. Последняя форма закрепляет за именем конкретный адрес, а имя нужно для проверки NS в апексе.

Флаги `check`:

| Флаг | Что делает |
|---|---|
| `--new` | серверы нового провайдера (обязательный) |
| `--old` | серверы старого провайдера; по умолчанию те, на которые сейчас делегирован домен |
| `--parent` | сервер родительской зоны, у которого спрашивать NS и DS; по умолчанию ищется через резолвер |
| `--zone-file` | zone-файл в формате BIND, выгруженный у старого провайдера |
| `--names` | дополнительные имена по одному в строке, относительно зоны (`@` это сама зона) |
| `--probe` | перебирать типовые метки и DKIM-селекторы (по умолчанию включено, `--probe=false` выключает) |
| `--wordlist` | свой список меток для перебора вместо встроенного |
| `--resolver` | рекурсивный резолвер, через который искать серверы, вместо системного |
| `--proxy-ranges` | файл с CIDR прокси вместо встроенного списка Cloudflare, или `none` |
| `--ttl` | как считать отличия только в TTL: `warn` (по умолчанию), `ignore`, `fail` |
| `--ignore` | принять известное отличие: `"www A"`, `"@ MX"` или просто `"staging"`; можно повторять |
| `--qps` | максимум запросов в секунду к одному серверу, по умолчанию 50, `0` без ограничения |
| `--concurrency` | сколько запросов одновременно в полёте на все серверы, по умолчанию 16 |
| `--timeout`, `--retries` | таймаут одной попытки (2s) и число повторов (2) |
| `--format` | `text` или `json` |

Коды выхода: 0, если блокеров нет; 1, если есть хотя бы один блокер; 2, если проверку не удалось провести (неверные аргументы, нет файла, не удалось определить старые серверы, прерывание по Ctrl-C).

`--format json` выводит всё то же самое без сокращений: полные значения DKIM, списки серверов, счётчики. Это удобно для скрипта, который должен остановить переезд:

```
dnscutover check example.com --new ns1.yandexcloud.net,ns2.yandexcloud.net \
  --zone-file example.com.zone --format json > cutover.json || exit 1
```

`dnscutover inventory` показывает только список имён и то, откуда каждое взялось. Это помогает понять, что попадёт в сравнение:

```
$ dnscutover inventory example.test --old ns1.olddns.test=127.0.0.1:5301 \
    --new ns1.newdns.test=127.0.0.1:5302 --zone-file testdata/lab/export.zone \
    --names testdata/lab/names.txt
example.test.                       apex,zone-file  A MX TXT CAA
_dmarc.example.test.                zone-file  TXT
_domainkey.example.test.            probe
mail._domainkey.example.test.       probe
selector1._domainkey.example.test.  zone-file  TXT
_autodiscover._tcp.example.test.    zone-file  SRV
api.example.test.                   zone-file  A
billing.example.test.               names-file
crm.example.test.                   zone-file  CNAME
mail.example.test.                  zone-file  A
staging.example.test.               probe
www.example.test.                   zone-file  CNAME

12 names: 8 zone-file, 1 names-file, 3 probe (139 labels probed)
```

## Как это работает

**Список имён.** Получить зону целиком через AXFR у публичных серверов обычно нельзя, поэтому список собирается из того, что есть. Это zone-файл (из него берутся и имена, и типы записей), файл `--names` и перебор встроенного словаря: около полутора сотен меток, включая DKIM-селекторы крупных почтовых сервисов и `_service._proto` для почты, SIP и календарей. Перебор идёт по первому старому и первому новому серверу. Перед ним запрашивается заведомо несуществующее случайное имя. Если на него приходит ответ, в зоне есть wildcard, и найденные перебором имена, ответ на которые совпадает с ответом wildcard, отбрасываются. У каждого имени в отчёте видно, откуда оно взялось.

**Опрос.** Для каждого имени спрашиваются A, AAAA, CNAME, MX, TXT и CAA, ниже апекса ещё NS, у имён с `_` ещё SRV, плюс типы, которые есть у этого имени в zone-файле. Каждый вопрос задаётся каждому серверу отдельно, без рекурсии, по UDP с EDNS0 (буфер 1232 байта). Если ответ обрезан (TC), запрос повторяется по TCP. Таймауты и потерянные пакеты повторяются. Запросы идут через пул из `--concurrency` горутин, а к каждому серверу не чаще `--qps` в секунду. Ctrl-C отменяет контекст: `miekg/dns` во время чтения учитывает только дедлайны сокета, поэтому при отмене сокет закрывается через `context.AfterFunc`, и висящие запросы завершаются сразу, а не по таймауту.

**Сравнение.** Ответы приводятся к каноническому виду: имена в нижнем регистре, адреса нормализованы, строки TXT склеены, порядок записей не важен, TTL хранится отдельно. Эталоном служит первый ответивший старый сервер. Остальные старые серверы сверяются с ним, и расхождения между ними показываются отдельно. Каждый новый сервер сравнивается с эталоном сам по себе, серверы с одинаковым результатом объединяются в одну находку. Поэтому запись, которой нет только на одном из новых серверов, видна сразу. Адреса из диапазонов прокси (по умолчанию встроенный список Cloudflare, источник и дата получения записаны в `internal/proxyrange/cloudflare.txt`) считаются ожидаемым изменением, кроме случая, когда имя является целью MX или SRV.

**Делегирование.** У сервера родительской зоны запрашиваются NS (из referral) и DS. У каждого нового сервера проверяется, что он отвечает на SOA зоны с флагом AA, и что серийные номера совпадают. Набор NS в апексе новой зоны сравнивается со списком новых серверов и со старыми. Для DNSKEY новой зоны считается DS-дайджест и сравнивается с DS у родителя. Если они не совпадают, в отчёте есть DS, который нужно опубликовать. Если NS-сервер находится внутри самой зоны, проверяется, что для него есть адрес и нужен glue. В конце печатаются TTL, от которых зависит, сколько будет «доезжать» переключение: TTL делегирования у родителя, негативный TTL новой зоны и самый большой TTL среди старых записей.

Код разбит на пакеты в `internal/`: `dnsq` (клиент), `inventory`, `compare`, `delegation`, `cutover` (сборка шагов и вердикт), `report`, `dnstest` (фейковый авторитативный сервер для тестов и лаборатории). Единственная прямая зависимость `github.com/miekg/dns`, она нужна для формата сообщений DNS и разбора zone-файлов.

## Ограничения

- Без zone-файла сравнение неполное: перебор находит только типовые имена. В лаборатории перебор без `--zone-file` находит почти всё, потому что имена там типовые. На реальном домене так не будет, поэтому в отчёт добавляется предупреждение `INVENTORY`.
- AXFR не поддерживается. Цели CNAME, MX и SRV внутри зоны автоматически в список имён не добавляются.
- Все запросы идут из одной точки сети. GeoDNS, балансировка с отдачей части адресов и ALIAS/flattening у разных провайдеров покажутся отличиями. Такие отличия нужно разобрать и принять через `--ignore`.
- DNSSEC проверяется только на уровне соответствия DS и DNSKEY. Подписи RRSIG не валидируются, для полной проверки цепочки есть DNSViz.
- Прокси распознаётся только по диапазонам адресов. Встроенный список только у Cloudflare, для других CDN нужен свой файл в `--proxy-ranges`.
- Записи HTTPS/SVCB по умолчанию не сравниваются, потому что провайдер с прокси может отдавать их для проксируемых имён сам. Они сравниваются, только если есть в zone-файле.
- Родительская зона ищется через резолвер. Если у домена сложное делегирование, лучше указать `--parent` явно.
- Локально тесты гонялись без `-race`: на машине разработки не было C-компилятора, а детектору гонок на Windows нужен cgo. `go test -race ./...` выполняется в CI на Linux.

## Разработка

```
go vet ./...
go test ./...
go test ./cmd/dnscutover -update   # перезаписать эталонные отчёты в cmd/dnscutover/testdata
```

Тесты не ходят в сеть. Все DNS-серверы поднимаются на 127.0.0.1 на свободных портах. Сквозные тесты гоняют обе версии лаборатории и сравнивают полный текстовый отчёт с эталоном.

## Лицензия

MIT, см. [LICENSE](LICENSE).
