# ICAP RESPMOD Server

Небольшой ICAP-сервер на Python, написанный в рамках тестового задания.

Сервер принимает HTTP-ответы через RESPMOD. Если тело начинается с `ENC1`, расшифровывает его с помощью AES-256-GCM. Если нет — возвращает без изменений. При ошибке расшифровки отвечает ICAP 400.

## Запуск

Нужен Python 3.12.

**Windows (PowerShell):**
```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe -m icap_server
```

**Linux:**
```bash
python3.12 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
.venv/bin/python -m icap_server
```

По умолчанию сервер слушает порт `1344`, сервис доступен по пути `/decrypt`.

## Тесты

**Windows (PowerShell):**
```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements-dev.txt
.\.venv\Scripts\python.exe -m pytest -q
```

**Linux:**
```bash
.venv/bin/python -m pip install -r requirements-dev.txt
.venv/bin/python -m pytest -q
```

Тесты сами запускают сервер, поэтому отдельно включать его не нужно. Проверяются работа с бинарными данными, расшифровка, обработка ошибок и обмен через настоящий TCP.

## Ручная проверка через CMD

Запустите сервер в первом терминале. Во втором терминале **CMD** откройте папку проекта и выполните одну из команд ниже. Дополнительный клиент не нужен.

**1. Обычные данные (ожидается `ICAP/1.0 200 OK`).** Отправляем `hello` и проверяем, что тело вернулось без изменений:

```cmd
.\.venv\Scripts\python.exe -c "import socket; s=socket.create_connection(('127.0.0.1',1344)); s.sendall(b'RESPMOD icap://localhost/decrypt ICAP/1.0\r\nHost: localhost\r\nConnection: close\r\nEncapsulated: res-hdr=0, res-body=38\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n5\r\nhello\r\n0\r\n\r\n'); s.shutdown(socket.SHUT_WR); print(b''.join(iter(lambda:s.recv(4096),b'')).decode('latin-1')); s.close()"
```

**2. Неверный тег AES-GCM (ожидается `ICAP/1.0 400 Bad Request`).** Отправляем ENC1 с корректной длиной, но недействительным тегом аутентификации:

```cmd
.\.venv\Scripts\python.exe -c "import socket; body=b'ENC1'+bytes(range(12))+bytes(16); http=b'HTTP/1.1 200 OK\r\nContent-Length: '+str(len(body)).encode()+b'\r\n\r\n'; icap=b'RESPMOD icap://localhost/decrypt ICAP/1.0\r\nHost: localhost\r\nConnection: close\r\nEncapsulated: res-hdr=0, res-body='+str(len(http)).encode()+b'\r\n\r\n'; req=icap+http+format(len(body),'x').encode()+b'\r\n'+body+b'\r\n0\r\n\r\n'; s=socket.create_connection(('127.0.0.1',1344)); s.sendall(req); s.shutdown(socket.SHUT_WR); print(b''.join(iter(lambda:s.recv(4096),b'')).decode('latin-1')); s.close()"
```

## Docker

```bash
docker build -t icap-decrypt .
docker run --rm -p 1344:1344 icap-decrypt
```

## Структура

- `icap_server/server.py` — TCP-сервер.
- `icap_server/protocol.py` — обработка ICAP.
- `icap_server/crypto.py` — расшифровка.
- `tests/` — автотесты.
