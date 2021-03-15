#!/usr/bin/env python3

from sql_functions import *
from modules_for_dlink import *
from netmiko import ConnectHandler, NetmikoTimeoutException, NetmikoAuthenticationException, ssh_exception
import pexpect
from paramiko import ssh_exception
import time
from datetime import datetime
import os
import re
import config
import subprocess
from multiprocessing import Pool
import telnetlib
from librouteros import plain, connect


USER = config.USERNAME_ROUTER
PASSWORD_OLD = config.PASSWORD_ROUTER_OLD
PASSWORD = config.PASSWORD_ROUTER_NEW



# Функция для пинга хоста
def ping_host(ip):

    """
    Пинг хоста, принимает ip хоста.
    Возвращает True или False в зависимости от результата
    """

    # Создаём список для передачи команды
    massive=['ping', '-c', '3', '-n', ip]
    result = subprocess.run([*massive], stdout=subprocess.PIPE, encoding='utf-8').returncode

    # Возвращает True если хости пингуется
    return True if not result else False


# Перезагрузка зивола
def reboot_zywall(ip, user=USER, password=PASSWORD):

    """
    Ребут хоста, принимает ip хоста, логин и пароль.
    Возвращает True или False в зависимости от результата
    """

    # Пробуем подключиться к хосту через ssh и выполнить команду
    try:
        with pexpect.spawn('ssh {}@{}'.format(user, ip), timeout=10) as ssh:
            ssh.expect('Password:')
            ssh.sendline(password)

            try:
                ssh.expect('[>]',timeout=5)
                time.sleep(0.5)
                ssh.sendline('reboot')
                time.sleep(0.5)

            except pexpect.exceptions.TIMEOUT:
                return False

    except:
        mess = f"Somethink went wrong while trying to reboot ZyWALL {ip}"
        write_log('reboot_zywall', '3', mess)
        return False

    time.sleep(1)

    # Если всё прошло без ошибок и хост не пингуется - возвращает True, иначе False
    return False if ping_host(ip) else True


# Перезагрузка микротика
def reboot_mikrotik(ip, user=USER, password=PASSWORD):

    """
    Ребут хоста, принимает ip хоста, логин и пароль.
    Возвращает True или False в зависимости от результата
    """
    try:
        # Порт для подключения
        port = '23'

        command_1 = 'system reboot'
        command_2 = 'y'

        # Создаём подключение с явно указанным портом и без
        tn = telnetlib.Telnet(ip, port, timeout=10)
        tn = telnetlib.Telnet(ip, timeout=10)

        # Вводим логин и пароль
        tn.read_until(b": ")
        tn.write(user.encode('UTF-8') + b"\n")
        tn.read_until(b"word: ")
        tn.write(password.encode('UTF-8') + b"\n")

        # Вводим команды
        tn.read_until(b'>')
        tn.write(command_1.encode('UTF-8') + b"\r\n")
        time.sleep(1)

        tn.write(command_2.encode('UTF-8') + b"\r\n")
        time.sleep(1)
    except:
        mess = f"Somethink went wrong while trying to reboot MikroTik {ip}"
        write_log('reboot_mikrotik', '3', mess)

        # Если хост не пингуется - возвращает True, иначе False
        return False if ping_host(ip) else True


# Вывод информации по dhcp с зивола
def get_dhcp_zywall(ip, user=USER, password=PASSWORD):

    """
    Запрос dhcp с зивола, принимает ip хоста, логин и пароль.
    Возвращает список или False в зависимости от результата
    """

    # Пробуем подключиться к хосту через ssh и выполнить команду
    try:
        with pexpect.spawn('ssh {}@{}'.format(user, ip), timeout=10) as ssh:
            ssh.expect('Password:')
            ssh.sendline(password)
            
            ssh.expect('[>]',timeout=5)
            time.sleep(0.5)

            ssh.sendline('show ip dhcp binding')
            time.sleep(0.5)
            ssh.expect('[>]',timeout=5)

            # Декодируем ответ и разбиваем по символам переноса строки
            result = ssh.before.decode('ascii').split('\n')

            # Переменная для временного хранения результатов
            itog = []

            # Ищем строки подходящие под шаблон
            for line in result[2:]:
                match = re.search('\d* +\S+ +(\S+) *(\S+) *\S+ *(\S+) *\S+ *\S+', line)

                # Если такая строка нашлась - добавляем переменные в список с заменой лишних символов
                if match:

                    # Добавляются данные в виде ip, mac, hostname
                    itog.append([match.group(1), match.group(2), match.group(3).replace("\"", ''), ])

            # Возвращаем список с результатами или пустой
            return itog if itog else ['0', '0', '0']

    # Если что-то пошло не так - возвращаем False
    except:
        mess = f"Somethink went wrong while trying to get dhcp from ZyWALL {ip}"
        write_log('get_dhcp_zywall', '3', mess)
        return False


# Функция вывода информации по dhcp с микрота
def get_dhcp_mikrotik(ip, user=USER, password=PASSWORD):

    """
    Запрос dhcp с микрота, принимает ip хоста, логин и пароль.
    Возвращает список или False в зависимости от результата
    """

    try:
        # Создаём переменную для подключения к микротику
        method = (plain, )

        # Создаём переменную для подключения к микротику
        api = connect(username = user, password = password, host = ip, login_methods = method, port = 8728)

        # Забираем через неё dhcp-таблицу
        result = api('/ip/dhcp-server/lease/print')

        # Создаём переменную для перебрасывания информации туда
        itog = []

        # Заносим туда значимую инфу
        for line in result:

            try:
                itog.append([line['address'], line['mac-address'], line['host-name'], ])

            # Обработка хостов без мак-адреса
            except KeyError:
                continue

        # Возвращаем список с результатами или пустой
        return itog if itog else ['0', '0', '0']

    # Если что-то пошло не так - возвращаем False
    except:
        mess = f"Somethink went wrong while trying to get dhcp from MikroTik {ip}"
        write_log('get_dhcp_mikrotik', '3', mess)
        return False


# Вывод информации по arp-таблице с зивола
def get_arp_zywall(ip, user=USER, password=PASSWORD):

    """
    Запрос arp с зивола, принимает ip хоста, логин и пароль.
    Возвращает список или False в зависимости от результата
    """

    # Пробуем подключиться к хосту через ssh и выполнить команду
    try:
        with pexpect.spawn('ssh {}@{}'.format(user, ip), timeout=10) as ssh:
            ssh.expect('Password:')
            ssh.sendline(password)
            try:
                ssh.expect('[>]',timeout=5)
                time.sleep(0.5)

                # Выводим арп-таблицу
                ssh.sendline('show arp-table')
                ssh.expect('[>]')
                time.sleep(0.5)

                # Сохраняем её в переменную
                result=ssh.before.decode('ascii').split('\n')

            except pexpect.exceptions.TIMEOUT:
                return False

        # Переменная для временного хранения результатов
        itog = []

        # Обрабатываем построчно вывод и добавляем в список
        for line in result[2:-1]:
            line = line.split()

            # Если арп недействителен - пропускаем его
            if 'incomplete' not in line[1]:
                itog.append([line[0], line[2],])

        return itog

    # Если что-то пошло не так - возвращаем False
    except:
        mess = f"Somethink went wrong while trying to get arp from ZyWALL {ip}"
        write_log('get_arp_zywall', '3', mess)
        return False


# Вывод информации по arp-таблице микрота
def get_arp_mikrotik(ip, user=USER, password=PASSWORD):

    """
    Запрос arp с микрота, принимает ip хоста, логин и пароль.
    Возвращает список или False в зависимости от результата
    """

    try:
        # Создаём переменную для подключения к микротику
        method = (plain, )

        # Создаём переменную для подключения к микротику
        api = connect(username = user, password = password, host = ip, login_methods = method, port = 8728)

        # Забираем через неё арп-таблицу
        result = api('/ip/arp/print')

        # Переменная для временного хранения результатов
        itog = []

        # Идём по полученному списку и проверяем, входят ли адреса в интересующий нас список
        for line in result:

            try:
                itog.append([line['address'], line['mac-address']])

            # Обработка на случай недействительных арпов
            except KeyError:
                continue

        return itog

    # Если что-то пошло не так - возвращаем False
    except:
        mess = f"Somethink went wrong while trying to get arp from MikroTik {ip}"
        write_log('get_arp_mikrotik', '3', mess)
        return False
    

# Функция для редактирования конфига зивола
def edit_rule_zywall(ip, New_info, condition, user=USER, password=PASSWORD):

    """
    Редактирование конфига зивола, принимает ip хоста, список команд, логин и пароль.
    Возвращает False или True в зависимости от результата
    """

    try:
        # Получаем список существующих правил
        firewall = get_firewall_zywall(ip, user, password)

        # Переменная для проверки, существует ли уже правило
        cool = False

        # Идём по списку правил
        for fire in firewall:

            # Сохраняем правило во временную переменную
            temp_fire = fire

            # Идём по шаблону нужного правила
            for i in condition.keys():

                # Убираем из правила строки, пустые в шаблоне
                if not condition[i]:
                    fire[i] = ''

            # Сравниваем получившееся правило с шаблоном
            if fire == condition:
                print(f"The rule is already exists on the host {ip}, its cool!")
                cool = True

        # Если правило уже есть - выходим из функции
        if cool:
            return True



        # Пробуем подключиться к хосту по ssh и выполнить команду
        with pexpect.spawn('ssh {}@{}'.format(user, ip), timeout=10) as ssh:
            ssh.expect('Password:')
            ssh.sendline(password)
            try:
                ssh.expect('[>]',timeout=5)
                time.sleep(0.5)

                ssh.sendline('configure terminal')
                time.sleep(0.5)
                ssh.expect('[#]',timeout=5)

                # Идём по списку команд
                for line in New_info:
                    ssh.sendline(line)
                    time.sleep(0.5)
                    ssh.expect('[#]',timeout=5)

                # Сохраняем изменения
                ssh.sendline('write')
                time.sleep(2)
                ssh.expect('[#]',timeout=5)

            except pexpect.exceptions.TIMEOUT:
                print('Ошибка на хосте', ip)
                return False

    # Если что-то пошло не так - возвращаем False
    except:
        mess = f"Somethink went wrong while trying to edit firewall on ZyWALL {ip}"
        write_log('edit_rule_zywall', '3', mess)
        print('Ошибка на хосте', ip)
        return False

    return True


# Функция для проверки хостов в сети
def checking_hosts_zywall(subnet, user=USER, password=PASSWORD):

    """
    Проверяет на зиволе, какие хосты активны в сети. Принимает подсеть, логин и пароль.
    Пишет данные в файл, может вернуть False в случае ошибки.
    """

    # Переменная для временного хранения данных
    temp_data = {}

    # Открываем файл и идём по строкам
    with open(f'/home/scripts/scripts/auto/counting_hosts_{subnet}.txt') as f:
        for line in f:

            # Разбиваем файл на строки, берём первое слово, ip, за ключ в словаре
            # Второе и третье, mac и сколько раз замечен хост, списком в значения
            line = line.split()
            temp_data[line[0]] = [line[1], line[2]]

    # Создаём пул на 8 процессов
    with Pool(processes=8) as pool:

        # Идём по списку роутеров
        for i in range(2, 255):

            # Запускаем функцию в многопотоке и передаём ей аргументы
            res = pool.apply_async(ping_host, (f"{subnet}.{i}", ))

        # Запускаем процессы и ждём пока отработают
        res.get()

    # Пробуем подключиться к хосту через ssh и выполнить команду
    try:
        with pexpect.spawn('ssh {}@{}'.format(user, f"{subnet}.1"), timeout=10) as ssh:
            ssh.expect('Password:')
            ssh.sendline(password)
            try:
                ssh.expect('[>]',timeout=5)
                time.sleep(0.5)

                # Выводим арп-таблицу
                ssh.sendline('show arp-table')
                ssh.expect('[>]')
                time.sleep(0.5)

                # Сохраняем её в переменную и разбиваем по строкам
                result=ssh.before.decode('ascii').split('\n')

            except pexpect.exceptions.TIMEOUT:
                return False

        # Отсекаем лишние первые и последнюю строки
        for line in result[2:-1]:
            checker = False

            # Разделяем строку по пробелам
            line = line.split()

            # Если ip нет в словаре - включаем переключатель
            if line[0] not in temp_data.keys():
                checker = True

            # Если арп не действителен, проверяем, был ли ip адрес ранее в словаре
            if line[1] == '(incomplete)':
                if checker:

                    # Если не был - добавляем его и помечаем, что замечен 0 раз
                    temp_data[line[0]] = [line[1], '0']

            # Если арп в порядке
            else:

                # И хоста нет в словаре - добавляем его и помечаем, что замечен один раз
                if checker:
                    temp_data[line[0]] = [line[2], '1']

                # Если хост уже был в словаре - прибавляем 1 к числу замеченных раз
                else:
                    temp_data[line[0]][1] = int(temp_data[line[0]][1]) + 1

        # Открываем файл и записываем туда новый словарь
        with open('/home/scripts/scripts/auto/counting_hosts.txt', 'w') as f:
            for line in sorted(temp_data.keys()):
                f.write(f"{line} {temp_data[line][0]} {temp_data[line][1]}" + '\n')

    # Если что-то пошло не так - возвращаем False
    except:
        mess = f"Somethink went wrong while trying to check hosts on ZyWALL {ip}"
        write_log('checking_hosts_zywall', '3', mess)
        return False


# Проверка наличия интернета на интерфейсах зивола
def check_inet_zywall(ip, user=USER, password=PASSWORD):

    """
    Проверяет инет на зиволе, принимает ip, логин и пароль.
    Возвращает список с результатами или False.
    """

    # Переменная для временного хранения результатов
    itog = []

    # Пробуем подключиться к хосту через ssh и выполнить команду
    try:
        with pexpect.spawn('ssh {}@{}'.format(user, ip), timeout=60) as ssh:
            ssh.expect('Password:')
            ssh.sendline(password)

            try:
                ssh.expect('[>]')
                time.sleep(0.5)

                # Выводим арп-таблицу
                ssh.sendline('show interface all')
                ssh.expect('[>]')
                time.sleep(0.5)

                # Сохраняем её в переменную
                result=ssh.before.decode('ascii')
                result=result.split('\n')

            except pexpect.exceptions.TIMEOUT:
                return False

            # Опускаем первые две строки и идём по остальным, проверяя совпадения
            for line in result[2:]:
                match = re.search('\d* +(\S+) +(\S+ \S+|\S+) *([\w.]+) *([\w.]+) *\D+', line)

                # Если совпадение обнаружено - проверяем, чтобы это был не пустой интерфейс
                if match:

                    # Проверка, активен ли интерфейс
                    checker_int = True
                    result_ping = ''

                    if match.group(3) == '0.0.0.0' and 'cellular' not in match.group(1):
                        continue

                    if (match.group(2) == 'Down' or         # Проверяем, активен ли интерфейс
                        match.group(2) == 'Disconnected' or # Не отключен ли ppp
                        match.group(3) == '0.0.0.0' or      # Не равен ли ip 0.0.0.0
                        match.group(2) == 'n/' or           # Нормальное ли имя интерфейса
                        match.group(2) == 'Inactive'):      # Активен ли интерфейс

                        # Если на что-то ответ да - присваиваем значение Мёртв и отключаем переключатель
                        res = 'Мёртв'
                        checker_int = False

                    # Если переключатель включен - проверяем интерфейс
                    if checker_int:
                        time.sleep(0.5)
                        ssh.sendline(f"ping 8.8.8.8 source {match.group(3)}")
                        ssh.expect('[>]')
                        time.sleep(0.5)

                        # Декодируем строку и разбиваем по символам переноса
                        result_ping=ssh.before.decode('ascii')

                    # Проверяем, есть ли потери пингов в ответе
                    if not result_ping or ', 100% packet loss' in result_ping:
                        res = 'Мёртв'

                    else:
                        res = 'Жив'

                    match = match.group(0).split()
                    match.append(res)
                    itog.append(match)

            return itog

    except:
        mess = f"Somethink went wrong while trying to check inet on ZyWALL {ip}"
        write_log('check_inet_zywall', '3', mess)
        return False


# Подключение к микроту по телнету для проверки пинга
def check_int_mikrotik_telnet(ip, interface, user, password):

    """
    Пингуем 1.1.1.1 с микрота, принимает ip хоста, интерфейс, логин и пароль.
    Возвращает Жив или Мёртв
    """

    # Задаём порт для подключения
    port = '23'
    
    # Список команд
    command_1 = f'ping 1.1.1.1 interface={interface} count=3'
    command_2 = 'quit'

    # Пробуем подключиться с портом и без
    tn = telnetlib.Telnet(ip, port)
    tn = telnetlib.Telnet(ip)

    # Вводим логин
    tn.read_until(b"Login: ")
    tn.write(user.encode('UTF-8') + b"\n")

    # Вводим пароль
    tn.read_until(b"Password: ")
    tn.write(password.encode('UTF-8') + b"\n")

    # Вводим команды
    tn.read_until(b'>')
    tn.write(command_1.encode('UTF-8') + b"\r\n")
    time.sleep(5)
    tn.read_until(b'>')
    tn.write(command_2.encode('UTF-8') + b"\r\n")

    # Считываем результаты, переводим в строку и разбиваем по символу переноса
    lines = tn.read_all()
    lines = str(lines).split('\\r')

    # Идём по строкам и проверяем, были ли 100% потери
    for line in lines:
        if "=\\x1b[m100%" in line:
            tn.close()
            return 'Мёртв'
    
    tn.close()
    return 'Жив'


# Проверка наличия интернета на интерфейсах микротах
def check_inet_mikrotik(ip, user=USER, password=PASSWORD):

    """
    Проверяет инет на микроте, принимает ip, логин и пароль.
    Возвращает список с результатами или False.
    """

    try:
        # Переменная для временного хранения результатов
        itog = []

        # Создаём переменную для подключения к микротику
        method = (plain, )

        # Создаём переменную для подключения к микротику
        api = connect(username = user, password = password, host = ip, login_methods = method, port = 8728)

        # Забираем таблицу адресов
        result = api('/ip/address/print')

        # Идём по списку результатов
        for line in result:

            # Если интерфейс - бридж, присваиваем ему значение мёртв и идём к следующему
            if line['actual-interface'] == 'bridge-master':
                itog.append(['', line['interface'], '', line['address'][:-3], 'Мёртв'])
                continue

            # Проверяем доступность интернета с интерфейса
            res = check_int_mikrotik_telnet(ip, line['actual-interface'], user, password)

            # Добавляем ответ в список, пустые места - для выравнивания с ответами от зивола
            itog.append(['', line['interface'], '', line['address'][:-3], res])

        
        return itog

    except:
        mess = f"Somethink went wrong while trying to check inet on MikroTik {ip}"
        write_log('check_inet_mikrotik', '3', mess)
        return False


# Настройка ssh на зиволе
def enable_ssh_zywall(ip, user=USER, password=PASSWORD):

    """
    Включает ssh на зиволе, принимает ip, логин и пароль.
    Возвращает True или False в зависимости от результата.
    """

    try:
        # Задаём порт для подключения
        port = '23'

        # Задаём команды для ввода
        command_1 = 'configure terminal'
        commands = ['ip ssh server', 'exit', 'write', ]

        # Пытаемся подключиться, все команды выполняем с таймаутом 5 сек
        tn = telnetlib.Telnet(ip, port, timeout=10)
        tn = telnetlib.Telnet(ip, timeout=10)

        # Вводим логин
        tn.read_until(b": ", timeout=10)
        tn.write(user.encode('UTF-8') + b"\n")

        # Вводим пароль
        tn.read_until(b"Password: ", timeout=10)
        tn.write(password.encode('UTF-8') + b"\n")

        # Вводим пароль
        tn.read_until(b">", timeout=10)
        tn.write(command_1.encode('UTF-8') + b"\n")

        # Идём по списку команд
        for command in commands:
            tn.read_until(b'#', timeout=10)
            tn.write(command.encode('UTF-8') + b"\r\n")

        tn.read_until(b'#', timeout=10)
        tn.close()

    # Если в ходе проверки возникла какая-то ошибка, возвращаем False
    except:
        mess = f"Somethink went wrong while trying to enable ssh on ZyWALL {ip}"
        write_log('enable_ssh_zywall', '3', mess)
        return False

    return True


# Настройка ssh на микротике
def enable_ssh_mikrotik(ip, command_1 = 'ip service print', user=USER, password=PASSWORD):

    """
    Включает ssh на микротике, принимает ip, логин и пароль.
    Возвращает True или False в зависимости от результата.
    """

    try:
        # Задаём порт для подключения
        port = '23'

        # Список команд
        command_2 = 'quit'

        # Пробуем подключиться с портом и без
        tn = telnetlib.Telnet(ip, port)
        tn = telnetlib.Telnet(ip)

        # Вводим логин
        tn.read_until(b": ")
        tn.write(user.encode('UTF-8') + b"\n")

        # Вводим пароль
        tn.read_until(b"Password: ")
        tn.write(password.encode('UTF-8') + b"\n")

        # Вводим команды
        tn.read_until(b'>')
        tn.write(command_1.encode('UTF-8') + b"\r\n")
        tn.read_until(b'>')
        tn.write(command_2.encode('UTF-8') + b"\r\n")

        # Проверяем, какая была команда
        if 'enable' not in command_1:

            # Считываем результаты, переводим в строку и разбиваем по символу переноса
            lines = tn.read_all()
            lines = str(lines).split('\\r')

            # Смотрим, какой номер у ssh сервиса
            for line in lines:
                if 'ssh' in line:
                    line = line.split()
                    break

            # Отправляем команду с номером ssh для включения
            enable_ssh_mikrotik(ip, f'ip service enable {line[1]}')

        # Если была команда на включение - выходим из цикла
        else:
            time.sleep(1)
            tn.close()
            return True
    
    except:
        mess = f"Somethink went wrong while trying to enable ssh on MikroTik {ip}"
        write_log('enable_ssh_mikrotik', '3', mess)
        return False


# Функция для получение ssh ключа
def ssh_key(ip, user=USER, checker=True ):

    """
    Получение ssh ключа, принимает ip и логин.
    Возвращает True или False в зависимости от результата.
    """

    # Пробуем подключиться к хосту через ssh и выполнить команду
    try:
        with pexpect.spawn('ssh {}@{}'.format(user, ip), timeout=10) as ssh:

            # Проверяем приветствие, если идёт запрос - принимаем его
            try:
                ssh.expect('[?]')
                ssh.sendline('yes')
                ssh.expect(':')
                return True

            # Если в процессе возникла ошибка, что этому хосту принадлежит другой ключ - удаляем старый
            except pexpect.exceptions.EOF:
                mess = f"Ssh key on the host {ip} has changed, delete the old key"
                write_log('ssh_key', '2', mess)
                os.system(f"ssh-keygen -f '/home/scripts/.ssh/known_hosts' -R '{ip}'")
                if checker:
                    ssh_key(ip, user, False)
                return True

            # Возникает ошибка, когда ключ уже есть или проблемы с хостом
            except:
                print("\nAlready have a key or host", ip, 'is broken')

    # Иногда ошибка вываливается на разных обработки
    except pexpect.exceptions.EOF:
        mess = f"Ssh key on the host {ip} has changed, delete the old key"
        write_log('ssh_key', '2', mess)
        os.system(f"ssh-keygen -f '/home/scripts/.ssh/known_hosts' -R '{ip}'")
        if checker:
            ssh_key(ip, user, False)
        return True

    # Если всё пошло не так
    except:
        mess = f"Some error on the host {ip} while trying to get the ssh key"
        write_log('ssh_key', '2', mess)
        return False


# Проверка\смена пароля на микроте
def check_mikrotik(ip, user=USER, password=PASSWORD_OLD, new_password=PASSWORD):

    """
    Проверка пароля на микротике, принимает ip, логин, старый пароль и новый.
    Возвращает True, False или Ошибка в зависимости от результата.
    """

    # Создаём словарь для подключения
    mikrotik = {'device_type': 'mikrotik_routeros',
                'ip': ip,
                'username': user,
                'password': password,
                'port': 22,
                'timeout': 10,
               }

    # Пробуем подключиться
    try:
        ssh = ConnectHandler(**mikrotik)

    # Если вернулись эти исключения - пароль неправильный
    except (NetmikoAuthenticationException, ssh_exception.AuthenticationException):
        return False

    # Другие исключения - что-то странное с хостом
    except:
        mess = f"Error on the MikroTik {ip} while checking the password"
        write_log('check_mikrotik', '3', mess)
        return 'Ошибка'

    # Если функция запускалась со старым паролем и подключилось успешно
    # Отправляем команду для смены пароля
    if password == PASSWORD_OLD:

        # Пробуем отправить команду со сменой пароля
        try:
            ssh.send_command(f"/password old-password={password} new-password={new_password} confirm-new-password={new_password}")

        # Иногда команда выполняется, но прилетает ошибка
        except:
            pass
        time.sleep(1)

    # Если всё прошло без ошибок - возвращаем True
    return True


# Проверка\смена пароля на зиволе
def check_zywall(ip, user=USER, password=PASSWORD_OLD):

    """
    Проверка пароля на зиволе, принимает ip, логин и пароль.
    Возвращает True, False, Ошибка или Ошибка подключения в зависимости от результата.
    """

    # Пробуем подключиться к хосту через ssh и выполнить команду
    try:
        with pexpect.spawn('ssh {}@{}'.format(user, ip), timeout=10) as ssh:
            ssh.expect('Password:')
            ssh.sendline(password)
            try:
                ssh.expect('[>]',timeout=5)
                time.sleep(0.5)

            # Если не увидим символ - возвращаем False
            except pexpect.exceptions.TIMEOUT:
                mess = f"Error on the ZyWALL {ip} while checking the password"
                write_log(sys.argv[0], '3', mess)
                return False

            # Если подключались со старым паролем и подключились успешно - выполняем команды для его смены
            if password == PASSWORD_OLD:
                ssh.sendline('configure terminal')
                ssh.expect('[#]')
                time.sleep(0.5)

                ssh.sendline(f"username admin password {PASSWORD} user-type admin")
                ssh.expect('#')
                time.sleep(0.5)

                ssh.sendline('write')
                ssh.expect('#')
                time.sleep(0.5)

            return True

    # Возвращаем ответ в зависимости от ошибки
    except pexpect.exceptions.TIMEOUT:
        mess = f"Error on the ZyWALL {ip} while checking the password"
        write_log('check_zywall', '3', mess)
        return 'Ошибка подключения'

    except:
        mess = f"Error on the ZyWALL {ip} while checking the password"
        write_log('check_zywall', '3', mess)
        print('Ошибка на хосте', ip)
        return 'Ошибка'


# Основная логика для проверки зивола
def rule_for_zywall(ip, user=USER, password=PASSWORD):

    """
    Смена пароля на зиволе, принимает ip, логин и пароль.
    Пишет в файл error_pass.log результат проверки, если он неудачен.
    """

    # Функция для проверки пароля
    result = check_zywall(ip, user, password)

    # Проверяем вернувшийся результат
    if result:
        if result == 'Ошибка подключения':
            print(f'Хост {ip} недоступен\n')
            return
        elif result == 'Ошибка':

            # Пишем в лог
            mess = f"Something wrong on the ZyWALL {ip} while checking the password"
            write_log('rule_for_zywall', '3', mess)
            return False

    else:
        result = check_zywall(ip)
        if result == True:

            # Пишем в лог
            mess = f"Changing the password on ZyWALL {ip} successed"
            write_log('rule_for_zywall', '1', mess)
            return True

        elif result == 'Ошибка':

            return False

        elif result == 'Ошибка подключения':

            return False

        elif result == False:

            # Пишем в лог
            mess = f"The old password did not work on ZyWALL {ip} too"
            write_log('rule_for_zywall', '3', mess)
            return False


# Основная логика для проверки микротика
def rule_for_mikrotik(ip, user=USER, password=PASSWORD):

    """
    Смена пароля на микротике, принимает ip, логин и пароль.
    Пишет в файл error_pass.log результат проверки, если он неудачен.
    """

    # Функция для проверки корректности введённого пароля
    result = check_mikrotik(ip, user, password)

    # Проверяем вернувшийся результат
    if result:

        if result == 'Ошибка':

            return False

        return True

    else:

        result = check_mikrotik(ip)
        if result == True:

            # Пишем в лог
            mess = f"Changing the password on MikroTik {ip} successed"
            write_log('rule_for_mikrotik', '1', mess)
            return True

        elif result == 'Ошибка':

            return False

        elif result == False:

            # Пишем в лог
            mess = f"The old password did not work on MikroTik {ip} too"
            write_log('rule_for_mikrotik', '3', mess)

            return False


# Включает порт для взаимодействия с микротиком через api
def set_api(ip):

    """
    Включение api на микротике, принимает ip.
    Ничего не возвращает из-за кривизны микрота.
    """

    # Список для подключея с разными паролями
    passwds = [PASSWORD_OLD, PASSWORD]

    # Идём про списку
    for passwd in passwds:

        # Создаём словарь для подключения
        mikrotik = {'device_type': 'mikrotik_routeros',
                    'ip': ip,
                    'username': USER,
                    'password': passwd,
                    'port': 22,
                    }

        # Пробуем ввести комадны через try, ибо микрот часто возвращает False даже на успешную команду
        try:
            ssh = ConnectHandler(**mikrotik)
        except:
            continue
        try:
            result = ssh.send_command('/ip service enable api')
        except IndexError:
            pass
        try:
            result = ssh.send_command('/ip service set api address=172.29.21.81,172.29.100.190,172.29.0.81')
        except IndexError:
            pass


# Пробуем подключиться к оборудованию и получить версию прошивки
def check_version(ip, model, user = USER, password = PASSWORD, checker = True):

    """
    Проверка прошивки роутера, принимает ip, модель, логин и пароль.
    Возвращает версию прошивки.
    """

    try:
        # Порт для подключения
        port = '23'

        # Для разных моделей разные команды
        if 'ZyWALL' in model:
            command_1 = 'show version'
            command_2 = 'exit'
        else:
            command_1 = 'system resource print'
            command_2 = 'quit'

        # Создаём подключение с явно указанным портом и без
        tn = telnetlib.Telnet(ip, port, timeout=10)
        tn = telnetlib.Telnet(ip, timeout=10)

        # Вводим логин и пароль
        tn.read_until(b": ")
        tn.write(user.encode('UTF-8') + b"\n")
        tn.read_until(b"word: ")
        tn.write(password.encode('UTF-8') + b"\n")

        # Вводим команды и обрабатываем строку в зависимости от модели
        tn.read_until(b'>')
        tn.write(command_1.encode('UTF-8') + b"\r\n")
        time.sleep(1)
        zywall = tn.read_until(b'>')

        tn.write(command_2.encode('UTF-8') + b"\r\n")
        mikrotik = tn.read_all()
        mikrotik = str(mikrotik).split('\\r')
        zywall = str(zywall).split('\\r')

        # Возвращает строку в завимости от модели
        return zywall if 'ZyWALL' in model else mikrotik
    except:

        # Пишем в лог
        mess = f"Some error on the host {ip} while trying to get firmware version"
        write_log('check_version', '3', mess)
        return False


# Проверяем, присутствует ли ip в списке и добавляем в базу, если нет
def check_ip(model, ip, routers):

    """
    Собираем данные с устройств, принимает модель, ip и список уже найденных роутеров.
    При необходимости обновляем\добавляем запись в базу.
    """

    # Получаем ssh ключ и проверяем пароль
    # Если устройство - микрот, настраиваем api
    if 'MikroTik' in model:
        ssh_key(ip)
        rule_for_mikrotik(ip)
        set_api(ip)
    elif 'ZyWALL' in model:
        ssh_key(ip)
        rule_for_zywall(ip)

    # Получаем версию прошивки
    result = check_version(ip, model)

    try:
        # В зависимости от модели обрабатываем строку и забираем из неё версию прошивки
        if model == 'MikroTik':
            regex_group = re.compile('version: (\S+) *\S+')
            for line in result:
                match = regex_group.search(line)
                if match:
                    version = match.group(1)
                    break

        elif ('110' in model) or ('USG20' in model):
            regex_group = re.compile('\d + (\S+ \S+|\S+) +(\S+) +\S+ \S+ +(\S+)')
            for line in result:
                match = regex_group.search(line)
                if match:
                    if match.group(3) == 'Running':
                        version = match.group(2)
                        break

        else:
            regex_group = re.compile('firmware version: (\S+)')
            for line in result:
                match = regex_group.search(line)
                if match:
                    version = match.group(1)
                    break

        # Идём по списку роутеров из базы
        for line in routers:
            if line[0] == ip:

                # Сверяем, если модель оборудования или прошивка не совпадает с записанной - обновляем запись
                if line[1] != model or line[2] != version:
                    router_to_sql(ip, model, version, 'UPDATE')

                return

        # Если ip адрес не нашёлся в списке - добавляем запись в базу
        router_to_sql(ip, model, version, 'INSERT')
        return

    except TypeError:
        mess = f"Some error on the host {ip} while trying to get the version"
        write_log('check_ip', '2', mess)
        return False


# Проверка хоста
def check_host(ip, routers):

    """
    Получает модель прошивки и отправляет данные для дальнейшей обработки.
    Принимает ip и список уже найденных устройств.
    Может вернуть False в случае ошибки.
    """

    # Пробуем подключиться к хосту с таймаутом в 10 секунд
    try:
        print('Try to connect on', ip)
        telnet = telnetlib.Telnet(ip, timeout=10)

    except:
        mess = f"Can't connect to {ip} via telnet"
        write_log('check_host', '3', mess)
        return False

    # Считывает приветствие и конвертируем в строку
    result = str(telnet.read_until(b':'))

    # В зависимости от ответа запускаем функцию с указанной моделью
    if 'ZyWALL USG 20' in result:
        model = 'ZyWALL USG 20'
        check_ip(model, ip, routers)

    elif 'ZyWALL USG 100' in result:
        model = 'ZyWALL USG 100'
        check_ip(model, ip, routers)

    elif 'ZyWALL USG100-PLUS' in result:
        model = 'ZyWALL USG100-PLUS'
        check_ip(model, ip, routers)

    elif 'ZyWALL 110' in result:
        model = 'ZyWALL 110'
        check_ip(model, ip, routers)

    elif 'USG20-VPN' in result:
        model = 'ZyWALL USG20-VPN'
        check_ip(model, ip, routers)

    elif 'MikroTik' in result or 'Login' in result:
        model = 'MikroTik'
        check_ip(model, ip, routers)
        
    elif 'Linux' in result:
        mess = f"Host {ip} is Linux"
        write_log(sys.argv[0], '2', mess)
        print(f"Host {ip} is Linux")
        return True

    else:
        mess = f"Host {ip} is strange"
        write_log(sys.argv[0], '2', mess)
        return True


# Поиск dlink с дефолтными настройками на зиволе
def find_bad_dlink_zywall(ip, user = USER, password = PASSWORD):

    """
    Поиск dlink-ов с дефолтными настройками, принимает ip хоста, логин и пароль.
    Пишет в файл dlink.txt результат проверки, если что-то нашлось.
    """

    # Список команд на выполнение
    commands = ['interface lan1:4',
                'ip address 10.90.90.100 255.0.0.0',
                'exit',
                'exit',
                'ping 10.90.90.90 source 10.90.90.100',
                ]

    # Пробуем подключиться к хосту через ssh и выполнить команду
    try:
        with pexpect.spawn('ssh {}@{}'.format(user, ip), timeout=20) as ssh:
            ssh.expect('Password:')
            ssh.sendline(password)

            try:
                ssh.expect('[>]')
                ssh.sendline('configure terminal')

            except pexpect.exceptions.TIMEOUT:
                return False

            # Идём по списку команд
            for command in commands:
                ssh.expect('#')
                time.sleep(0.5)
                ssh.sendline(command)

            # Декодируем результаты пинга
            ssh.expect('#')
            time.sleep(0.5)
            result = ssh.before.decode('ascii')

            # Если там 100% потери - ничего не делаем
            if '100% packet loss' in result:
                print(f'На зиволе {ip} пусто')
                pass

            # Иначе пишем в файл, что нашли длинк
            else:
                with open ('dlink.txt', 'a') as f:
                    print(f'D-Link finding on host {ip} !!!!!!', file=f)

            # Заходим в конфиг и убираем созданный интерфейс
            ssh.sendline('configure terminal')

            ssh.expect('#')
            time.sleep(0.5)
            ssh.sendline('no interface lan1:4')

            ssh.expect('#')
            time.sleep(0.5)

            return True

    except:
        return False


# Поиск dlink с дефолтными настройками на микроте
def find_bad_dlink_mikrotik(ip, user = USER, password = PASSWORD):

    """
    Поиск dlink-ов с дефолтными настройками, принимает ip хоста, логин и пароль.
    Пишет в файл dlink.txt результат проверки, если что-то нашлось.
    """

    method = (plain, )

    # Создаём словарь для подключения
    mikrotik = {'device_type': 'mikrotik_routeros',
                'ip': ip,
                'username': user,
                'password': password,
                'port': 22,
               }

    # Пробуем подключиться с игнором ошибок, которые любит возвращать микрот
    try:
        ssh = ConnectHandler(**mikrotik)
    except:
        pass

    # Создаём интерфейс для поиска длинка
    try:
        add_ip = ssh.send_command('/ip address add address=10.90.90.92 netmask=255.255.255.0 interface=bridge-master')
    except:
        pass

    # Пингуем длинк
    try:
        add_ip = ssh.send_command('/ping 10.90.90.90 count=4')
    except:
        pass

    # Создаём второе подключение для получения результатов
    api = connect(username = user, password = password, host = ip, login_methods = method, port = 8728)

    # Ждём пока пройдут пинги
    time.sleep(5)

    # Выводим содержимое арпа
    result = api('/ip/arp/print')

    # Идём по списку и смотрим результат пинга
    for line in result:
        if line['address'] == '10.90.90.90':
            try:

                # Если у адреса есть мак - значит, нашёлся
                if line['mac-address']:

                    # Записываем найденный длинк в файл
                    with open('dlink.txt', 'a') as f:
                        print(f"D-Link finding in host {ip} !!!!!!", file=f)
            except:
                pass

    # Выводим список адресов микрота
    result = api('/ip/address/print')

    # Смотрим, какое id у созданного интерфейса
    for line in result:
        if line['address'] == '10.90.90.92/24':

            # Удаляем его
            try:
                add_ip = ssh.send_command(f"/ip address remove {line['.id']}")
            except:
                pass

    # Ждём пока отработает удаление
    time.sleep(2)
    print(f'Микрот {ip} проверен')


# Проверка активных портов на зиволе
def get_ports_zywall(ip, model, user = USER, password = PASSWORD):

    """
    Проверка активных портов на зиволе, принимает ip хоста, модель, логин и пароль.
    Возвращает сумму всех активных портов и ван портов или False в случае ошибки.
    """

    # Пробуем подключиться к хосту через ssh и выполнить команду
    try:
        with pexpect.spawn('ssh {}@{}'.format(user, ip), timeout=20) as ssh:
            ssh.expect('Password:')
            ssh.sendline(password)

            try:
                ssh.expect('[>]')
                time.sleep(0.5)
                ssh.sendline('show port status')

            except pexpect.exceptions.TIMEOUT:
                return False

            ssh.expect('[>]')

            # Декодируем вывод списка портов и разделяем по строкам
            result=ssh.before.decode('ascii').split('\n')

            # Переменные для хранения суммы интерфейсов
            sum_all = 0
            sum_wan = 0

            # Смотрим модель и от этого считаем число WAN портов
            if '20' in model:
                wan = ('1')
            elif '100' in model:
                wan = ('1', '2')
            else:
                wan = ('1', '2', '3')

            # Идём по списку строк и ищем совпадение
            for line in result[2:]:
                match = re.search('(\d*) +(\S+) +(\d*) *(\d*) *(\d*) *(\d*) *(\d*) *(\S+)', line)

                # Если нашли - проверяем в каком он состоянии и если активен - плюсуем к сумме
                if match:
                    if match.group(1).isdigit() and match.group(2) != 'Down':
                        if match.group(1) in wan:
                            sum_wan += 1
                        sum_all += 1

        return sum_all, sum_wan

    except:
        return False


# Проверка активных портов на микроте
def get_ports_mikrotik(ip, user = USER, password = PASSWORD):

    """
    Проверка активных портов на зиволе, принимает ip хоста, логин и пароль.
    Возвращает сумму всех активных портов и ван портов или False в случае ошибки.
    """

    try:

        # Переменные для хранения суммы интерфейсов
        sum_all = 0
        sum_wan = 0

        # Создаём переменную для подключения к микротику
        method = (plain, )

        # Создаём переменную для подключения к микротику
        api = connect(username = user, password = password, host = ip, login_methods = method, port = 8728)

        # Забираем таблицу адресов
        result = api('/interface/print')

        # Идём по списку результатов
        for line in result:
            try:

                # Если нашли - проверяем в каком он состоянии и если активен - плюсуем к сумме
                if 'ether' in line['default-name'] and line['running']:
                    if 'WAN' in line['name']:
                        sum_wan += 1
                    sum_all += 1
            except KeyError:
                continue

        return sum_all, sum_wan

    except:
        return False


# Получение списка с фаерволом с зивола
def get_firewall_zywall(ip, user = USER, password = PASSWORD):

    """
    Получение списка правил на зиволе, принимает ip хоста, логин и пароль.
    Возвращает список правил в виде [{action, destination ip, rule, service, source ip, source port, to}, ..]
    или False в случае ошибки.
    """


    # Пробуем подключиться к хосту через ssh и выполнить команду
    try:
        with pexpect.spawn('ssh {}@{}'.format(user, ip), timeout=20) as ssh:
            ssh.expect('Password:')
            ssh.sendline(password)

            try:
                ssh.expect('[>]')
                time.sleep(0.5)
                ssh.sendline('show firewall')

            except pexpect.exceptions.TIMEOUT:
                return False

            ssh.expect('[>]')
            time.sleep(0.5)

            # Декодируем результат и разбиваем по строкам
            result=ssh.before.decode('ascii').split('\n')
    except:
        return False

    # Переменная для хранения результатов и счётчик
    itog = []
    k = -1

    # Идём по списку правил
    for line in result:

        # Разбиваем строку по запятым и идём по этим строкам
        line = line.split(',')
        for word in line:

            # Разделяем описание и значение
            word = word.split(':')

            # Если значение есть - заменяем лишние символы и убираем пробелы
            try:
                if word[1]:
                    word[1] = word[1].replace('\r','')
                    word[1] = word[1].strip()

            except IndexError:
                continue

            # Проверяем, не началось ли новое правило
            if 'secure-policy rule' in word[0] or 'firewall rule' in word[0]:

                # Если да - увеличиваем счётчик, добавляем новый словарь и номер правила
                k += 1
                itog.append({})
                itog[k]['rule'] = k + 1

            # В зависимости от пункта правила добавляем значение
            elif 'from' in word[0]:
                itog[k]['from'] = word[1]

            elif 'to' in word[0]:
                itog[k]['to'] = word[1]

            elif 'source IP' in word[0]:
                itog[k]['source ip'] = word[1]

            elif 'source port' in word[0]:
                itog[k]['source port'] = word[1]

            elif 'destination IP' in word[0]:
                itog[k]['destination ip'] = word[1]

            elif 'service' in word[0]:
                itog[k]['service'] = word[1]

            elif 'action' in word[0]:
                itog[k]['action'] = word[1]

    return itog


# Получение конфига с микротика и сохранение в файл
def get_config_mikrotik(ip, user = USER, password = PASSWORD):

    try:

        # Порт для подключения, список команд
        port = '23'
        command_1 = 'export compact'
        command_2 = 'quit'

        # Создание подключения
        tn = telnetlib.Telnet(ip, port)
        tn = telnetlib.Telnet(ip)

        # Ввод логина и пароля
        tn.read_until(b": ")
        tn.write(user.encode('UTF-8') + b"\n")
        tn.read_until(b"Password: ")
        tn.write(password.encode('UTF-8') + b"\n")

        # Отправка команд
        tn.read_until(b'>')
        tn.write(command_1.encode('UTF-8') + b"\r\n")
        tn.read_until(b'>')
        tn.write(command_2.encode('UTF-8') + b"\r\n")

        # Считываем результат и закрываем соединение
        lines = tn.read_all().decode('UTF-8')
        time.sleep(1)
        tn.close()

        # Сохраняем результат в текстовый файл и считываем обратно
        config = f"backup/config_{ip}.txt"
        with open (config, 'w') as f:
            print(lines, file=f)
        conf = open(config).readlines()

        # Удаляем из файла лишние строки и записываем обратно
        for i in [0, 0, 0, 0, 0, 0, 0, 0, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1]:
            conf.pop(i)
        with open(config, 'w') as f:
            f.writelines(conf)
            
        return
    
    except:
        print(f"Something wrong on MikroTik {ip}")


# Получение конфига с микротика и сохранение в файл
def get_config_zywall(ip, user = USER, password = PASSWORD):

    try:
        with pexpect.spawn('ssh {}@{}'.format(user, ip)) as ssh:
            try:
                ssh.expect('Password:')
                ssh.sendline(password)
            except (pexpect.exceptions.TIMEOUT):
                print ("\nCan't connect to {}".format(ip))
                return
            ssh.expect('[>]')
            time.sleep(0.5)

            ssh.sendline('show running-config')
            ssh.expect('[>]')

            result = ssh.before.decode('ascii')

            with open (f"backup/config_{ip}.txt", "w") as f:
                print(result[22:-9], file=f)
                
            return

    except:
        pass


# Поиск wifi точки на зиволе
def check_good_wifi_zywall(ip, wifis_db, user=USER, password=PASSWORD):

    # Шаблон для поиска ответа на пинг
    regex_group = re.compile('(\S+) +\w+ +(\S+) +\S +\S+')

    # Шаблон для запуска пинга с сервера
    massive=['ping', '-c', '2', '-n', '']

    # Делим адрес на октеты и создаём с ними список для пинга
    net = ip.split('.')
    wifis = [f'172.{net[1]}.{net[2]}.10', f'172.{net[1]}.{net[2]}.11',  f'172.{net[1]}.{net[2]}.12', ]

    try:
        with pexpect.spawn('ssh {}@{}'.format(user, ip)) as ssh:
            try:
                ssh.expect('Password:')
                ssh.sendline(password)
            except (pexpect.exceptions.TIMEOUT):
                mess = f"Cant connect to ZyWALL {ip} to find a good wifi"
                write_log('check_good_wifi_zywall', '3', mess)
                return False
            ssh.expect('[>]')
            time.sleep(0.5)

            # Пингуем список адресов с сервера, чтобы на зиволе появились арпы с мак-адресами
            for ip_ping in wifis:
                massive[4]=(ip_ping)
                result = subprocess.run([*massive], stdout=subprocess.PIPE, encoding='utf-8')

            print(f'\nChecking host {ip}')

            # Выводим арп-таблицу
            ssh.sendline('show arp-table')
            ssh.expect('[>]')
            time.sleep(0.5)

            # Сохраняем её в переменную
            result=ssh.before.decode('ascii')
            result=result.split('\n')
            # Идём в цикле по переменной и сравниваем с шаблоном для поиска хостов
            for line in result:

                # Переменная для проверки, существует ли найденное устройство в списке
                check = True
                
                # Заглушка, пока нет возможности определять модель wifi точки
                model = ''

                match = regex_group.search(line)
                if match:

                    # Если совпало с интересующим нас адресом - проверяем, нет ли этого длинка в списке
                    if match.group(1) in wifis:

                        for wifi_db in wifis_db:

                            # Проверяем, если ли найденный адрес в базе
                            if match.group(1) == wifi_db[0]:

                                # Проверяем, совпадают ли у них мак адреса
                                if match.group(2) == wifi_db[1]:

                                    # Если всё одинаковое - выходим из цикла
                                    check = False
                                    break

                                # Если мак адреса разные - обновляем инфо в базе
                                else:
                                    check = False
                                    wifi_to_sql(match.group(1), match.group(2), model, 'UPDATE')

                        # Если хоста нет в базе - добавляем его
                        if check:
                            wifi_to_sql(match.group(1), match.group(2), model, 'INSERT')

    except:
        mess = f"Wrong password or ZySH daemon is dead on ZyWALL {ip}"
        write_log('check_good_wifi_zywall', '3', mess)
        print("\nWrong password or ZySH daemon is dead on ZyWALL", ip)
        return False


# Поиск wifi точки на микротике
def check_good_wifi_mikrotik(ip, wifis_db, user=USER, password=PASSWORD):

    # Шаблон для запуска пинга с сервера
    massive=['ping', '-c', '2', '-n', '']

    # Создаём переменную для подключения к микротику
    method = (plain, )

    # Делим адрес на октеты и создаём с ними список для пинга
    net = ip.split('.')
    wifis = [f'172.{net[1]}.{net[2]}.10', f'172.{net[1]}.{net[2]}.11',  f'172.{net[1]}.{net[2]}.12']

    try:

        # Пингуем список адресов с сервера, чтобы на микротике появились арпы с мак-адресами
        for ip_ping in wifis:
            massive[4]=(ip_ping)
            result = subprocess.run([*massive], stdout=subprocess.PIPE, encoding='utf-8')

        print(f'\nChecking host {ip}')

        # Создаём переменную для подключения к микротику
        api = connect(username = user, password = password, host = ip, login_methods = method, port = 8728)

        # Забираем через неё арп-таблицу
        result = api('/ip/arp/print')

        # Идём по полученному списку и проверяем, входят ли адреса в интересующий нас список
        for line in result:

            # Переменная для проверки, существует ли найденное устройство в списке
            check = True
                
            # Заглушка, пока нет возможности определять модель wifi точки
            model = ''

            if line['address'] in wifis:
                try:

                    # Если такой адрес находится, проверяем, есть ли у него мак адрес
                    if line['mac-address']:

                        for wifi_db in wifis_db:

                            # Проверяем, если ли найденный адрес в базе
                            if line['address'] == wifi_db[0]:

                                # Проверяем, совпадают ли у них мак адреса
                                if line['mac-address'] == wifi_db[1]:

                                    # Если всё одинаковое - выходим из цикла
                                    check = False
                                    break

                                # Если мак адреса разные - обновляем инфо в базе
                                else:
                                    check = False
                                    wifi_to_sql(line['address'], line['mac-address'], model, 'UPDATE')

                        # Если хоста нет в базе - добавляем его
                        if check:
                                    wifi_to_sql(line['address'], line['mac-address'], model, 'INSERT')

                except:
                    pass

        print(f"Done with host {ip}")

    except:
        mess = f"Somethink wrong with MikroTik {ip}"
        write_log('check_good_wifi_mikrotik', '3', mess)
        return False


# Проверка, на каком интерфейсе ZyWALL поднят ipsec
def check_ipsec_zywall(ip, user = USER, password = PASSWORD):

    """
    Проверяет инет на зиволе, принимает ip, логин и пароль.
    Возвращает список с результатами или False.
    """

    # Переменная для временного хранения результатов
    interfaces = []

    # Пробуем подключиться к хосту через ssh и выполнить команду
    try:
        with pexpect.spawn('ssh {}@{}'.format(user, ip), timeout=60) as ssh:
            ssh.expect('Password:')
            ssh.sendline(password)

            try:
                ssh.expect('[>]')
                time.sleep(0.5)

                # Выводим арп-таблицу
                ssh.sendline('show interface all')
                ssh.expect('[>]')
                time.sleep(0.5)

                # Сохраняем её в переменную
                result=ssh.before.decode('ascii').split('\n')

            except pexpect.exceptions.TIMEOUT:
                return False

            # Опускаем первые две строки и идём по остальным, проверяя совпадения
            for line in result[2:]:
                match = re.search('\d* +(\S+) +(\S+ \S+|\S+) *([\w.]+) *([\w.]+) *\D+', line)

                # Если совпадение обнаружено - добавляем интерфейс в список
                if match and match.group(2) != 'n/' and match.group(2) != 'Inactive' and match.group(2) != 'connected':

                    interfaces.append([match.group(1), match.group(2), match.group(3), match.group(4)])

            # Выводим vpn-gateway подключения
            ssh.sendline('show isakmp sa')
            ssh.expect('[>]')
            time.sleep(0.5)

            # Сохраняем её в переменную
            result=ssh.before.decode('ascii').split('\n')

            # Идём по строкам ответа и проверяем, какой ip интерфейса в них
            for line in result:
                for inter in interfaces:
                    if inter[2] in line:
                        return inter

    except:
        mess = f"Something wrong on the ZyWALL {ip} while checking the ipsec"
        write_log('check_ipsec_zywall', '3', mess)
        return


# Проверка, на каком интерфейсе MikroTik поднят ipsec
def check_ipsec_mikrotik(ip, user = USER, password = PASSWORD):

    """
    Проверка активных портов на зиволе, принимает ip хоста, логин и пароль.
    Возвращает сумму всех активных портов и ван портов или False в случае ошибки.
    """
    try:
        # Создаём переменную для подключения к микротику
        method = (plain, )

        # Создаём переменную для подключения к микротику
        api = connect(username = user, password = password, host = ip, login_methods = method, port = 8728)

        # Забираем таблицы интерфейсов и ipsec-ов
        interfaces = api('/ip/address/print')
        ipsec = api('/ip/ipsec/installed-sa/print')

        # Меняем генератор на обычный список
        interface = [x for x in interfaces]

        # Идём по списку поднятых ipsec
        for line in ipsec:

            # Проверяем, на каком адресе висит и возвращаем ответ
            for inter in interface:

                if inter['address'][:-3] == line['src-address'].split(':')[0]:
                    return inter

    except:
        mess = f"Something wrong on the MikroTik {ip} while checking the ipsec"
        write_log('check_ipsec_mikrotik', '3', mess)
        return False


# Проверка, на каком канале сидит роутер
def check_ipsec_active(ip, model, debug=False):

    """
    Проверка роутеров, не сидят ли они на USB модеме, принимает ip и модель.
    Возвращает True или False в зависимости от результата
    """
    try:
        # Подключаемся к базе и получаем прошлый список с активными инет-интерфейсами
        cursor = connect_to_DB()
        old_inter = get_inet_inter(cursor, ip)

        # Идём в зависимости от модели
        if 'ZyWALL' in model:

            # Получаем список инет-интерфейсов
            result = check_inet_zywall(ip)

            # Соединяем их в одну строку с разделителем
            inter=';'.join(x[1] for x in result if x[-1] == 'Жив')

            # Получаем интерфейс, с которого поднят IP SEC
            ipsec = check_ipsec_zywall(ip)

            # Если в базе не было этого хоста или записей о нём - вставляем новые данные
            if not old_inter and inter:
                inter_to_sql(cursor, ip, inter, 'INSERT')
                old_inter = get_inet_inter(cursor, ip)

            # Если новые данные не соответствуют старым
            elif old_inter != inter:
                inter_to_sql(cursor, ip, inter, 'UPDATE')

            # Если инет-интерфейсов больше одного и IP SEC поднят на USB модеме - действуем
            if len(inter.split(';')) > 1 and 'cellular' in ipsec[0]:
                print(f"IP SEC на хосте {ip} поднят с {ipsec[0]} {ipsec[2]}, хотя активны {inter}")
                mess = f"IP SEC на хосте {ip} поднят с {ipsec[0]} {ipsec[2]}, хотя активны {inter}"
                write_log('check_ipsec_active', '3', mess)

            # Если было больше одного интерфейса, а остался один, и это USB модем - действуем
            elif (len(old_inter.split(';')) > 1 and
                  len(inter.split(';')) == 1 and
                  'cellular' in ipsec[0]):

                print(f"На роутере {ip} отвалился основной канал, пыхтим на {ipsec[0]}!")
                mess = f"На роутере {ip} отвалился основной канал, пыхтим на {ipsec[0]}!"
                write_log('check_ipsec_active', '3', mess)

            if debug:
                print(f"С хостом {ip} {model} всё ок {inter}, {ipsec[0]}")


        # Всё аналогично для микрота
        elif 'MikroTik' in model:

            result = check_inet_mikrotik(ip)
            inter=';'.join(x[1] for x in result if x[-1] == 'Жив')

            ipsec = check_ipsec_mikrotik(ip)

            if not old_inter:
                inter_to_sql(cursor, ip, inter, 'INSERT')
                old_inter = get_inet_inter(cursor, ip)

            elif old_inter != inter:
                inter_to_sql(cursor, ip, inter, 'UPDATE')

            if len(inter.split(';')) > 1 and (ipsec['interface'] == 'ppp-3g' or ipsec['interface'] == 'lte1'):
                print(f"IP SEC на хосте {ip} поднят с {ipsec['interface']} {ipsec['address'][:-3]}, хотя активны {inter}")
                mess = f"IP SEC на хосте {ip} поднят с {ipsec['interface']} {ipsec['address'][:-3]}, хотя активны {inter}"
                write_log('check_ipsec_active', '3', mess)

            elif (len(old_inter.split(';')) > 1 and
                  len(inter.split(';')) == 1 and
                  (ipsec['interface'] == 'ppp-3g' or ipsec['interface'] == 'lte1' or ipsec['interface'] == 'ppp-out1')):

                print(f"На роутере {ip} отвалился основной канал, пыхтим на {ipsec['interface']}!")
                mess = f"На роутере {ip} отвалился основной канал, пыхтим на {ipsec['interface']}!"
                write_log('check_ipsec_active', '3', mess)

            if debug:
                print(f"С хостом {ip} {model} всё ок {inter}, {ipsec['interface']}")

        cursor.close()
        return True

    except:
        mess = f"Some error on the host {ip} while trying to check ipsec"
        write_log('check_ipsec_active', '2', mess)
        print(f"На хосте {ip} что-то пошло не так")
        cursor.close()
        return False


# Проверка, активно ли устройство
def check_active_device(device, ip, active):

    """
    Проверка в сети ли устройств, принимает уровень устройства, ip адрес и текущее значение активности.
    Пишет результаты в базу, может вернуть ошибку.
    """
    try:

        # Пингуем устройство и получаем результат
        result = ping_host(ip)

        # Если пингов нет - прибавляем к имеющемуся числу 1 и пишем в базу
        if not result:
            active = int(active) + 1
            active_to_sql(device, ip, active)

        # Если пинги есть, проверяем, были ли они в прошлый раз
        else:

            # Если пингов не было - перезаписываем значение
            if active:
                active_to_sql(device, ip, 0)

    except:
        mess = f"Some error on the host {ip} while trying to get activity"
        write_log('check_active_device', '2', mess)
        return False



if __name__ == '__main__':

    pass
