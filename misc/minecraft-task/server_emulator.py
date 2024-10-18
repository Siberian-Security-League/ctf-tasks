from ldap3 import Server, Connection, ALL
from urllib.parse import urlparse
import subprocess
import httpx
import os
import socket
import uuid
import asyncio
import re


async def funcia(ip_addr):
    # Замените на адрес вашего LDAP-сервера
    #print(type(ldap_addr), str(ip_addr))
    server_address = f'{ip_addr}'  # или IP-адрес вашего LDAP-сервера
    server_port = 1389  # Порт по умолчанию для marshalsec LDAP-сервера

    # Создаем серверный объект
    server = Server(server_address, port=server_port, get_info=ALL)

    # Создаем подключение
    conn = Connection(server)
    try:
        # Открываем соединение
        conn.open()
        print('Подключено к LDAP-серверу.')

        # Выполняем поиск объекта
        dn = 'cn=foo'  # Замените на нужный вам DN

        # Выполняем поиск
        conn.search(
            search_base=dn,
            search_filter='(objectClass=*)',
            search_scope='BASE',
            attributes=['*']
        )

        print('Поиск выполнен.')

        if conn.entries:
            for entry in conn.entries:
                print('Найдена запись:')
                print(entry.entry_to_json())  # Выводим запись в формате JSON

                entry_dict = entry.entry_attributes_as_dict

                java_codebase = entry_dict.get('javaCodeBase', [None])[0]
                java_factory = entry_dict.get('javaFactory', [None])[0]

                if java_codebase and java_factory:
                    file_url = str(os.path.join(java_codebase, java_factory + '.class'))
                    print(f'Сформированный URL: {file_url}')
                    async with httpx.AsyncClient() as client:
                        response = await client.get(file_url)
                    if response.status_code == 200:
                        os.makedirs("download", exist_ok=True)
                        random_uuid = uuid.uuid4()
                        file_hashed_name = "download/" + java_factory + "." + str(random_uuid) + ".class"
                        with open(file_hashed_name, 'wb') as f:
                            f.write(response.content)
                        print(f'Файл {file_hashed_name} успешно загружен.')
                        #print("Файл якобы загружен")
                        os.makedirs("output", exist_ok=True)
                        subprocess.run([f'java -jar cfr-0.152.jar download/Exploit.{random_uuid}.class --outputpath ./output/Exploit.{random_uuid}.java.d'], shell=True)
                        regex_string = r'[0-9]{3,5}'
                        result = subprocess.run([f"cat output/Exploit.{random_uuid}.java.d/Exploit.java | grep -Eo {regex_string}"], shell=True, capture_output=True, text=True)
                        #print(result.stdout.split("\n"))
                        ports = [int(x) for x in result.stdout.split("\n") if x != '']
                        ports.sort(reverse=True)
                        print(ports)
                        #input()
                        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                            parsed_url = urlparse(java_codebase)
                            ip_address = parsed_url.hostname
                            for port in ports:
                                try:
                                    s.connect((ip_address, port))
                                    string_to_send = os.getenv('FLAG') + "\n"
                                    s.sendall(string_to_send.encode("utf-8"))
                                    print(f"Отправлен флаг на ip:{ip_address}; port:{port}")
                                    break
                                except Exception as e:
                                    print(e)
                                    pass
                    else:
                        print(f'Ошибка при загрузке файла: {response.status_code}')
                else:
                    print('Не удалось извлечь атрибуты javaCodeBase или javaFactory.')
        else:
            print('Записи не найдены.')

    except Exception as e:
        print(f'Ошибка при подключении или поиске: {e}')
    finally:
        conn.unbind()
        print('Соединение с LDAP-сервером закрыто.')

async def monitor_logs():
    command = "tail -f -n 10 /app/data/logs/latest.log"

    process = await asyncio.create_subprocess_shell(
        command,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE
    )
    tasks = set()

    try:
        while True:
            line = await process.stdout.readline()
            if line:
                line = line.decode('utf-8').rstrip()
                print(f"Получена строка: {line}")
                if re.search(r'\$\{jndi:(ldap|rmi|dns):\/\/', line):
                    pattern_ip = r'(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}' \
                              r'(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)'
                    matches = re.finditer(pattern_ip, line)
                    for match in matches:
                        ip_address = match.group(0)
                        break
                    task = asyncio.create_task(funcia(str(ip_address)))
                    tasks.add(task)
                    tasks = {t for t in tasks if not t.done()}
            else:
                if process.returncode is not None:
                    break
                else:
                    await asyncio.sleep(0.1)
    except asyncio.CancelledError:
        process.terminate()
        await process.wait()
        raise
    finally:
        await asyncio.gather(*tasks, return_exceptions=True)

async def main():
    task = asyncio.create_task(monitor_logs())
    try:
        await task
    except KeyboardInterrupt:
        task.cancel()
        await task
        print("Выход из программы...")

if __name__ == '__main__':
    asyncio.run(main())

