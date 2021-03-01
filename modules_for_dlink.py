#!/usr/bin/env python3

from pysnmp.hlapi import *
from pprint import pprint
from pysnmp.hlapi import getCmd, nextCmd, SnmpEngine, CommunityData, UdpTransportTarget, ContextData, ObjectType, ObjectIdentity
from pysnmp.carrier.asyncore.dispatch import AsyncoreDispatcher
from pysnmp.carrier.asyncore.dgram import udp
from pyasn1.codec.ber import encoder, decoder
from pysnmp.proto import api
from sql_functions import *
import time
import os
import re
import config
import datetime
import telnetlib


SNMP_PUBLIC = config.SNMP_PUBLIC
SNMP_PRIVATE = config.SNMP_PRIVATE
USERNAME_DLINK = config.USERNAME_DLINK
PASSWORD_DLINK_OLD = config.PASSWORD_DLINK_OLD
PASSWORD_DLINK_NEW = config.PASSWORD_DLINK_NEW


#######################################################################################
# Основные функции для получения информации об устройстве
# Без них не будут работать остальные


def get_model_snmp(ip, com_data=SNMP_PUBLIC):

    """
    Получение модели и перевод SNMP ответа в удобочитаемый вид, принимает ip адрес хоста
    Возвращает модель.
    """

    # Подключаемся к хосту и получаем snmp ответ
    for (errorIndication,
         errorStatus,
         errorIndex,
        varBinds) in getCmd(SnmpEngine(),
                          CommunityData(com_data),
                          UdpTransportTarget((ip, 161)),
                          ContextData(),
                          ObjectType(ObjectIdentity('.1.3.6.1.2.1.1.1.0'))):

        # Выводим ошибку в случае чего
        if errorIndication or errorStatus:
            print(errorIndication or errorStatus, ip)
            break

        else:

            for line in varBinds:
                # Конвертируем ответ в строку для работы с ним и разделяем по знаку '='
                #print(line)
                line = str(line).split('=')

                # Проверяем, является ли хост HP
                if 'HP' in line[1] or 'ProCurve' in line[1]:
                    model = line[1].split(',')[0]
                    return model.strip()

                # Для всех остальных подходит такое деление
                else:
                    model = line[1].split()[0]

                    # Если хост DGS - урезаем лишние символы
                    if 'DGS-1210-10P' in line[1]:
                        return model
                    if 'DGS-1100-08' in line[1]:
                        return model
                    if 'DGS' in line[1]:
                        return model[4:-3]
                    if 'DES-1210-28/ME/B' in line[1]:
                        return model[:-3]
                    if 'DES' not in line[1]:
                        return line[1].strip()
                    return model.strip()


def get_object_snmp(ip, com_data=SNMP_PUBLIC):

    """
    Получение версии прошивки устройства, принимает ip адрес хоста
    Возвращает модель и версию прошивки.
    """


    # Словарь с перечислением, какой результат какой прошивке соответствует
    objects = {'171.10.153.7.1': 'FX', # DGS-1210-52
               '171.10.153.5.1': 'FX', # DGS-1210-28
               '171.10.75.15.2': 'B2', # DES-1210-28/ME
               '171.10.75.15.3': 'B3', # DES-1210-28/ME
               '171.10.75.15': 'A1',   # DES-1210-28 | DES-1210-28/ME
               '171.10.75.5.2': 'BX',  # DES-1210-28
               '171.10.75.18.1': 'CX', # DES-1210-28
               '171.10.75.5' : 'AX',   # DES-1210-28
               '171.10.75.7': 'BX',    # DES-1210-52
               '171.10.75.20.1': 'CX', # DES-1210-52
               '171.10.75.19.1': 'C2', # DES-1210-28P
               '171.10.75.6' : 'A1',   # DES-1210-28P
               '171.10.76.12': '3.10', # DGS-1210-10P
               '171.10.134.20': 'B1',  # DGS-1100-08
               '171.10.75.4': '1.11',  # DES-1252
               '11.2.3.7.11.105': 'K.15.30',        # HP-6600
               '11.2.3.7.11.63': 'N.11.75',         # HP-2810
               '11.2.3.7.11.139': 'YA.16.03.0005',  # HP-2530
               '11.2.3.7.11.129': 'RA.16.02.0008',  # HP-2620
               '43.1.8.62': '01.00.09', # 3Com
               '43.1.8.62': '01.00.08'  # 3Com
               }

    # Подключаемся к хосту и получаем snmp ответ
    for (errorIndication,
         errorStatus,
         errorIndex,
        varBinds) in getCmd(SnmpEngine(),
                          CommunityData(com_data),
                          UdpTransportTarget((ip, 161)),
                          ContextData(),
                          ObjectType(ObjectIdentity('.1.3.6.1.2.1.1.2.0'))):

        # Выводим ошибку в случае чего
        if errorIndication or errorStatus:
            #print(errorIndication or errorStatus, ip)
            model = 'error'
            object = 'error'
            return model, object

        else:

            for line in varBinds:
                # Конвертируем ответ в строку для работы с ним
                line = str(line)
                #print(line)

                # Получаем модель хоста
                model = get_model_snmp(ip)

                # Проверяем, какой прошивке соответствует результат
                for item in objects:

                    # Если нашли - присваиваем и выходим из цикла
                    if item in line:
                        object = objects[item]
                        break

                    # Если нет - присваиваем ошибку
                    else:
                        object = 'error'

        return model, object


#######################################################################################


def get_firmware_snmp(ip, com_data=SNMP_PUBLIC):

    """
    Проверяем прошивку модели, нужно для некоторых модулей, принимает ip адрес.
    Возвращает True если прошло без ошибок, False - если есть ошибка, или заданный ответ.
    """


    # Подключаемся к хосту и получаем snmp ответ
    for (errorIndication,
         errorStatus,
         errorIndex,
        varBinds) in getCmd(SnmpEngine(),
                          CommunityData(com_data),
                          UdpTransportTarget((ip, 161)),
                          ContextData(),
                          ObjectType(ObjectIdentity('.1.3.6.1.4.1.171.10.75.15.2.1.3.0'))):

        # Выводим ошибку в случае чего
        if errorIndication or errorStatus:
            return errorIndication or errorStatus

        else:

            for line in varBinds:
                # Конвертируем ответ в строку и забираем последнюю часть
                line = str(line).split(' ')[2]

                # Получаем модель хоста
                model, object = get_object_snmp(ip)
                m_f = model + ' ' + object

                # Обрабатываем вариант для *ME B2 моделей
                if m_f == 'DES-1210-28/ME B2':

                    # Разделяем прошивку на части и проверяем вторую часть записи
                    line = line.split('.')[1]
                    
                    # Если там число - в зависимости от него возвращаем ответ
                    if line.isdigit():
                        if int(line) >= 10:
                            return 'ME new'
                        else:
                            return 'ME old'


        return True


def get_port_sec_all_snmp(ip, oid, com_data=SNMP_PUBLIC):

    """
    Проверка настроек port-security всех портов на хосте.
    Возвращает список с состоянием port-security и количеством разрешённых хостов.
    """

    # Создаём переменную для выхода из цикла и проверки, когда сменится snmp код
    check_exit = False
    check_spisok = False

    # Переменная для возвращения результатов и индекс вложенного списка
    result = [[]]
    i = 0

    # Подключаемся к хосту и получаем snmp ответ
    for (errorIndication,
         errorStatus,
         errorIndex,
        varBinds) in nextCmd(SnmpEngine(),
                          CommunityData(com_data),
                          UdpTransportTarget((ip, 161)),
                          ContextData(),
                          ObjectType(ObjectIdentity(oid))):

        # Выводим ошибку в случае отсутствия ответа от хоста
        if errorIndication or errorStatus:
            print(errorIndication or errorStatus)
            break

        else:

            for line in varBinds:

                # Конвертируем ответ в строку для работы с ним
                line = str(line)

                # Защита на случай, если пошли другие snmp с таким же форматом
                if oid[12:-2] not in line:
                    check_exit = True
                    break

                # Проверяем, перешёл ли snmp ответ к следующей переменной, максимуму хостов
                # Если да - создаём вложенный список и пишем данные в него
                if oid[12:] not in line and not check_spisok:
                    result.append([])
                    i += 1
                    check_spisok = True

                # Разделяем snmp ответ и записываем в список переменную с ответом
                result[i].append(line.split('=')[1][1:])

        # Если включилась переменная выхода из цикла - прекращаемм snmp опрос
        if check_exit:
            break

    # Возвращаем список с результатами
    return result


def get_port_sec(ip, oid):

    """
    Записывает\обновляет в базе информацию о настройках, принимает ip адрес хоста и oid.
    """

    # Подключение к базе
    # Возвращает список вида [ [ID устройства, порт, статус, максимум хостов], ...]
    cursor = connect_to_DB()
    port_sec_sql = get_port_sec_from_sql(cursor, ip)

    # Через исключение пробуем получить настройки port-security на хосте
    try:

        # Подключаемся к хосту и забираем данные в список
        result = get_port_sec_all_snmp(ip, oid)

        # Идём по списку и выводим результаты
        for port in range(len(result[0])):

            # При необходимости можно исключить из вывода порты с включеным port-security
            # и последние четыре порта (аплинки)
            # if result[0][port] != '1' and port < len(result[0]) - 4:
            #print(f"На порту {port+1} port security {'включен' if result[0][port] == '1' else 'выключен'} "
            #      f"и максимум {result[1][port]} хостов")

            # Переключатель, определяет, нужно ли добавлять данные в таблицу
            check = True

            # Идём по списку настроек port security из базы
            for port_sql in port_sec_sql:

                # Если в списке уже есть порт - проверяем его настройки
                if port_sql[1] == port + 1:

                    # Временная переменная для хранения состояния port security на порту
                    temp_status = 1 if result[0][port] == '1' else 0

                    # Проверяем, совпадают ли настройки порта из базы и текущие
                    if port_sql[2] != int(temp_status) or port_sql[3] != int(result[1][port]):

                        # Если нет - обновляем запись в базе
                        port_sec_to_sql(ip, port+1, temp_status, result[1][port], 'UPDATE')

                    # Поскольку порт нашёлся в базе - меняем состояние переключателя и выходим из цикла
                    check = False
                    break

            # Если данные в таблице не нашлись - добавляем их
            if check:
                port_sec_to_sql(ip, port+1, 1 if result[0][port] == '1' else 0, result[1][port], 'INSERT')

    except:
        print(f"Somethink wrong on host {ip}")

    cursor.close()


def get_port_sec_one_snmp(ip, oid, port, com_data=SNMP_PUBLIC):

    """
    Проверка настроек port-security одного порта на хосте, принимает ip хоста, oid и порт.
    Возвращает два параметра, состояние и количество хостов.
    """

    # Создаём список для результатов
    result = []

    # Подключаемся к хосту и получаем snmp ответ
    for (errorIndication,
         errorStatus,
         errorIndex,
        varBinds) in getCmd(SnmpEngine(),
                          CommunityData(com_data),
                          UdpTransportTarget((ip, 161)),
                          ContextData(),
                          ObjectType(ObjectIdentity(f"{oid}.{port}")),          # Запрашиваем состояния порта
                          ObjectType(ObjectIdentity(f"{oid[:-2]}.3.{port}"))):  # Запрашиваем количество разрешённых хостов на порту

        # Выводим ошибку в случае отсутствия ответа от хоста
        if errorIndication or errorStatus:
            print(errorIndication or errorStatus)
            break

        else:

            for line in varBinds:

                # Конвертируем ответ в строку для работы с ним
                line = str(line)

                # Записываем в список результат опросов
                result.append(line.split('=')[1][1:])

    # Возвращаем список с результатами, сначала состояние, потом количество хостов
    return result[0], result[1]


def set_port_sec_snmp(ip, oid, port, state=1, hosts=5, com_data=SNMP_PRIVATE):

    """
    Настройки port-security, принимает ip хоста, oid, порт, состояние и количество хостов
    Может вернуть ошибку
    """

    # Подключаемся к хосту и получаем snmp ответ
    for (errorIndication,
         errorStatus,
         errorIndex,
         varBinds) in setCmd(SnmpEngine(),
                          CommunityData(com_data),
                          UdpTransportTarget((ip, 161), timeout=5, retries=3),
                          ContextData(),
                          ObjectType(ObjectIdentity(f'{oid}.{port}'), Integer32(state)),            # Включаем\выключаем port-security
                          ObjectType(ObjectIdentity(f'{oid[:-2]}.3.{port}'), Integer32(hosts))):    # Указываем число хостов на порту

        # Возвращаем ошибку в случае отсутствия ответа от хоста
        if errorIndication or errorStatus:
            return errorIndication or errorStatus


def set_port_sec(ip, oid, state=1, hosts=5):

    """
    Изменение настроек port-security на хостах, принимает ip хоста, oid, состояние и количество хостов.
    В текущем виде пропускает порты где уже включено port security и аплинки.
    Возвращает результат в виде вывода на экран.
    """

    try:
        print('\n', '=' * 110)
        print('\nПодключаемся к хосту', ip, '\n')

        # Подключаемся к функции и забираем данные в список
        result = get_port_sec_all_snmp(ip, oid)

        # Идём по списку и выводим результаты
        for port in range(len(result[0])):

            # Задать условие для обработки портов, например, не обрабатывать порты с уже включеным port-security
            # и последние четыре порта (аплинки)
            if result[0][port] != '1' and port < len(result[0]) - 4:

                # Выводим старые настройки
                print(f"Было: На порту {port+1} port security {'включен' if result[0][port] == '1' else 'выключен'} "
                      f"и максимум {result[1][port]} хостов")

                # Вызываем функцию для изменения настроек
                set_port_sec_snmp(ip, oid, port+1, state, hosts)

                # Получаем новые настройки с конкретного порта для проверки
                new_state, new_hosts = get_port_sec_one_snmp(ip, oid, port+1)

                # Выводим новые значения
                print(f"Стало: На порту {port+1} port security {'включен' if new_state == '1' else 'выключен'} "
                      f"и максимум {new_hosts} хостов\n")

    except:
        print('\n', '=' * 110,)
        print('Error')


def save_config_snmp(ip, oid, value=1, com_data=SNMP_PRIVATE):

    """
    Сохранение конфига через snmp, принимает ip хоста и oid
    Может вернуть ошибку.
    """

    # Подключаемся к хосту и получаем snmp ответ
    for (errorIndication,
         errorStatus,
         errorIndex,
         varBinds) in setCmd(SnmpEngine(),
                          CommunityData(com_data),
                          UdpTransportTarget((ip, 161), timeout=5, retries=3),
                          ContextData(),
                          ObjectType(ObjectIdentity(oid), Integer32(value))):  # Сохраняем конфиг

        # Возвращаем ошибку в случае отсутствия ответа от хоста
        if errorIndication or errorStatus:
            return errorIndication or errorStatus


def save_conf(ip, oid):

    """
    Сохранение конфига, принимает ip хоста и oid.
    Возвращает успех или ошибку.
    """

    result = save_config_snmp(ip, oid)
    return 'Success!' if not result else f'{result}'


def get_loca_name_snmp(ip, oid, com_data=SNMP_PUBLIC):

    """
    Чтение локации свитча, принимает ip хоста и oid.
    Возвращает название локации либо None, если там пусто.
    """

    # Подключаемся к хосту и получаем snmp ответ
    for (errorIndication,
         errorStatus,
         errorIndex,
        varBinds) in getCmd(SnmpEngine(),
                          CommunityData(com_data),
                          UdpTransportTarget((ip, 161)),
                          ContextData(),
                          ObjectType(ObjectIdentity(oid))):  # Запрашиваем название локации

        # Выводим ошибку в случае отсутствия ответа от хоста
        if errorIndication or errorStatus:
            print(errorIndication or errorStatus)
            break

        else:

            for line in varBinds:

                # Конвертируем ответ в строку для работы с ним и убираем лишнее
                line = str(line).split('=')[1].lstrip()

    # Возвращаем результат
    return line if len(line) != 0 else 'None'


def set_pass_snmp(ip, oid, new_pass, com_data=SNMP_PRIVATE):

    """
    Сохранение конфига, принимает ip хоста, oid и новый пароль.
    Может вернуть ошибку.
    """

    # Подключаемся к хосту и получаем snmp ответ
    for (errorIndication,
         errorStatus,
         errorIndex,
         varBinds) in setCmd(SnmpEngine(),
                          CommunityData(com_data),
                          UdpTransportTarget((ip, 161), timeout=5, retries=3),
                          ContextData(),
                          ObjectType(ObjectIdentity(f'{oid}.'), OctetString(new_pass))):  # Отправляем новый пароль

        # Возвращаем ошибку в случае отсутствия ответа от хоста
        if errorIndication or errorStatus:
            return errorIndication or errorStatus


def set_pass_telnet(ip, old_pass, new_pass, user=USERNAME_DLINK):

    """
    Смена пароля на D-Link */ME, принимает ip хоста, старый и новый пароль.
    Возвращает 'Success', 'Fail' или 'Неправильный пароль' в зависимости от результата.
    """

    try:
        port = '23'

        # Задаём команды для ввода
        command_1 = 'config account admin'
        command_2 = 'save'

        # Пытаемся подключиться, все команды выполняем с таймаутом 5 сек
        tn = telnetlib.Telnet(ip, port, timeout=5)
        tn = telnetlib.Telnet(ip, timeout=5)

        # Вводим логин
        tn.read_until(b": ", timeout=5)
        tn.write(user.encode('UTF-8') + b"\n")

        # Вводим пароль
        tn.read_until(b"Password: ", timeout=5)
        tn.write(old_pass.encode('UTF-8') + b"\n")

        # Считываем результат после ввода пароля
        lines_1 = tn.read_until(b'#', timeout=5)
        tn.write(command_1.encode('UTF-8') + b"\r\n")

        # Считываем вывод после попытки поменять пароль на учётке и вводим подтверждения
        lines_2 = tn.read_until(b'old password:', timeout=3)
        tn.write(old_pass.encode('UTF-8') + b"\r\n")
        tn.read_until(b'new password:', timeout=3)
        tn.write(new_pass.encode('UTF-8') + b"\r\n")
        tn.read_until(b'mation:', timeout=3)
        tn.write(new_pass.encode('UTF-8') + b"\r\n")
        tn.read_until(b'#', timeout=3)
        tn.write(command_2.encode('UTF-8') + b"\r\n")
        tn.read_until(b'#', timeout=5)
        tn.close()

        # Если стандартный пароль не подходит, возвращаем 'Wrong password'
        if 'Incorrect' in str(lines_1):
            return 'Неправильный пароль'

        # Если учётки не существует - вызываем функию по её созданию
        elif 'does not exist' in str(lines_2):
            print('Нет учётки админа на устройстве, пытаюсь создать')
            res = create_acc_telnet(ip, old_pass, new_pass)
            if res == 'Fail':
                return 'Fail'
        return 'Success'

    # Если в ходе проверки возникла какая-то ошибка, возвращаем 'Fail'
    except:
        return 'Fail'


def create_acc_telnet(ip, old_pass, new_pass, user=USERNAME_DLINK):

    """
    Создание учётки админа на D-Link */ME по телнету, принимает ip хоста, старый и новый пароль.
    Возвращает 'Success' или 'Fail' в зависимости от результата
    """

    try:
        port = '23'

        # Задаём команды для ввода
        command_1 = 'create account admin admin'
        command_2 = 'save'

        # Пытаемся подключиться, все команды выполняем с таймаутом 5 сек
        tn = telnetlib.Telnet(ip, port, timeout=5)
        tn = telnetlib.Telnet(ip, timeout=5)

        # Вводим логин
        tn.read_until(b": ", timeout=5)
        tn.write(user.encode('UTF-8') + b"\n")

        # Вводим пароль
        tn.read_until(b"Password: ", timeout=5)
        tn.write(old_pass.encode('UTF-8') + b"\n")

        # Вводим команды для создания учётки
        tn.read_until(b'#', timeout=5)
        tn.write(command_1.encode('UTF-8') + b"\r\n")
        tn.read_until(b'new password:', timeout=5)
        tn.write(new_pass.encode('UTF-8') + b"\r\n")
        tn.read_until(b'mation:', timeout=5)
        tn.write(new_pass.encode('UTF-8') + b"\r\n")
        tn.read_until(b'#', timeout=5)
        tn.write(command_2.encode('UTF-8') + b"\r\n")
        tn.read_until(b'#', timeout=5)
        tn.close()

        return 'Success'

    except:
        return 'Fail'


def set_pass(ip, oid_pass, oid_save, old_pass=PASSWORD_DLINK_OLD, new_pass=PASSWORD_DLINK_NEW):

    """
    Смена пароля на устройстве, принимает ip хоста, oid для смены пароля и сохранения конфига, старый и новый пароль.
    Возвращает результат в виде вывода на экран.
    """

    try:
        # Для моделей, у которых отсутствует oid
        if oid_pass == '0':
            print(ip, end=', ')
            res_change = set_pass_telnet(ip, old_pass, new_pass)
            print('change successfull, save successfull!' if res_change == 'Success' else 'что-то пошло не так')

        # Для устройств с нормальным snmp
        else:
            print(ip, end=', ')

            # Меняем пароль
            res_change = set_pass_snmp(ip, oid_pass, new_pass)
            print('change successfull' if not res_change else f'{res_change}', end=', ')

            res_save = save_config_snmp(ip, oid_save)
            print('save successfull!' if not res_save else f'{res_save}')

    except:
        print('Error')
        return


def get_LBD_snmp(ip, oid, com_data=SNMP_PUBLIC):

    """
    Проверка настроек loopback detection всех портов на хосте по snmp, принимает ip хоста и oid
    Возвращает список с состоянием loopback detection и количеством разрешённых хостов
    """

    # Переменная для возвращения результатов
    result = []

    # Подключаемся к хосту и получаем snmp ответ
    for (errorIndication,
         errorStatus,
         errorIndex,
        varBinds) in nextCmd(SnmpEngine(),
                          CommunityData(com_data),
                          UdpTransportTarget((ip, 161)),
                          ContextData(),
                          ObjectType(ObjectIdentity(oid))):

        # Выводим ошибку в случае отсутствия ответа от хоста
        if errorIndication or errorStatus:
            print(f"{ip} {errorIndication or errorStatus}")
            break

        else:

            for line in varBinds:

                # Конвертируем ответ в строку для работы с ним
                line = str(line)

                # Защита на случай, если пошли другие snmp с таким же форматом
                if oid[12:] not in line:
                    return result

                # Разделяем snmp ответ и записываем в список переменную с ответом
                result.append(line.split('=')[1][1:])

    # Возвращаем список с результатами
    return result


def get_LBD(ip, oid):

    """
    Проверка настроек loopback detection всех портов на хосте, принимает ip хоста и oid
    Возвращает результат в виде вывода на экран.
    """

    try:
        # Подключаемся к функции и забираем данные в список
        result = get_LBD_snmp(ip, oid)

        # Проверяем, сколько вернулось позиций в snmp ответа для корректировки сдвига на некоторых моделях
        if len(result) % 3 == 0:
            i = -1
        else:
            i = 0

        # Определяем количество портов и вносим поправку, если необходимо
        ports = int((len(result) - 3 - i)  / 3)

        # Выводим общую информацию по LBD на устройстве
        #print(f"На устройстве {ip} {'включен' if result[0] == '1' else 'выключен'} LBD по "
        #      f"{'портам' if result[1] == '1' else 'vlan-ам'} с временем восстановления петли {result[3 + i]} секунд")

        # Выводим информацию по каждому порту на устройстве
        for port in range(1, ports + 1):

            # Выводим информацию, только если на порту есть петля
            if result[ports + ports + 3 + i + port ] != '1':
                print(f"У хоста {ip} на порту {result[port + 3 + i]} LBD {'включен' if result[ports + 3 + i + port] == '1' else 'выключен'}, "
                      f"сейчас петля {'отсутствует' if result[ports + ports + 3 + i + port ] == '1' else 'присутствует'}")

    except:
        print('Error on host', ip)
        pass


def set_LBD_global_snmp(ip, oid, diff, state=1, com_data=SNMP_PRIVATE):

    """
    Глобальные настройки LBD по snmp, принимает ip хоста, oid, время восстановления и состояние.
    Может вернуть ошибку.
    """

    # Подключаемся к хосту и получаем snmp ответ
    for (errorIndication,
         errorStatus,
         errorIndex,
         varBinds) in setCmd(SnmpEngine(),
                          CommunityData(com_data),
                          UdpTransportTarget((ip, 161), timeout=5, retries=3),
                          ContextData(),
                          ObjectType(ObjectIdentity(f'{oid}.1.0'), Integer32(state)),           # Включение\отключение LBD
                          ObjectType(ObjectIdentity(f'{oid}.2.0'), Integer32(1)),               # Проверка по портам
                          ObjectType(ObjectIdentity(f'{oid}.{diff}.0'), Integer32(100000))):    # Время восстановления

        # Возвращаем ошибку в случае отсутствия ответа от хоста
        if errorIndication or errorStatus:
            return errorIndication or errorStatus


def set_LBD_port_snmp(ip, oid, port, diff, state=1, com_data=SNMP_PRIVATE):

    """
    Настройка LBD на одном порту, принимает ip хоста, oid, номер порта, время восстановления и состояние
    Может вернуть ошибку
    """

    # Подключаемся к хосту и получаем snmp ответ
    for (errorIndication,
         errorStatus,
         errorIndex,
         varBinds) in setCmd(SnmpEngine(),
                          CommunityData(com_data),
                          UdpTransportTarget((ip, 161), timeout=5, retries=3),
                          ContextData(),
                          ObjectType(ObjectIdentity(f"{oid}.{diff}.1.2.{port}"), Integer32(state))):    # Включение\отключение LBD

        # Возвращаем ошибку в случае отсутствия ответа от хоста
        if errorIndication or errorStatus:
            return errorIndication or errorStatus


def set_LBD_telnet(ip, ports, user=USERNAME_DLINK, password=PASSWORD_DLINK_OLD):

    """
    Настройка LBD на D-Link */ME, принимает ip хоста, ограничение по какой порт включать, логин и пароль
    Возвращает 'Success' или 'Fail' в зависимости от результата
    """

    try:
        port = '23'

        # Задаём команды для ввода
        commands = ['config loopdetect enable','enable loopdetect', 'config loopdetect mode portbase',
                    'config loopdetect lbd_recover_time 10000 interval_time 1',
                    'config loopdetect lbd_recover_time 100000 interval_time 1',
                    'config stp ports 1-28 state disable', 'config stp ports 1-28 disable'
                    f'config loopdetect ports 1-{ports} state enable',
                    f'config loopdetect ports 1-{ports} enable', 'save']

        # Пытаемся подключиться, все команды выполняем с таймаутом 5 сек
        tn = telnetlib.Telnet(ip, port, timeout=5)
        tn = telnetlib.Telnet(ip, timeout=5)

        # Вводим логин
        tn.read_until(b": ", timeout=5)
        tn.write(user.encode('UTF-8') + b"\n")

        # Вводим пароль
        tn.read_until(b"Password: ", timeout=5)
        tn.write(password.encode('UTF-8') + b"\n")

        # Ввод команд в цикле
        for command in commands:
            tn.read_until(b'#', timeout=5)
            tn.write(command.encode('UTF-8') + b"\r\n")

        tn.read_until(b'#', timeout=5)
        tn.close()

        return 'Success'

    # Если в ходе проверки возникла какая-то ошибка, возвращаем 'Мёртв'
    except:
        return 'Fail'


def set_LBD(ip, model, oid_LBD, oid_STP, oid_save):

    """
    Настройка LBD, принимает ip хоста, модель, oid для LBD, STP, сохранения конфига
    Может вывести ошибку
    """

    try:
        print(model, ip, end=', ')

        # Отключаем STP на устройстве
        set_stp_snmp(ip, oid_STP)

        # Подключаемся к функции и забираем данные в список
        result = get_LBD_snmp(ip, oid_LBD)

        # Модели для работы по telnet
        teln = ['DES-1210-28 A1', 'DES-1210-28/ME A1', 'DES-1210-28/ME B2', 'DES-1210-28/ME B3']

        # Модели D-Link с адекватными oid
        standart = ['DES-1210-28 CX', 'DES-1210-52 CX']

        # Если текущий D-Link входит в число адекватных - ставим ему 5 в oid, иначе - 4
        if model in standart:
            diff = 5
        else:
            diff = 4

        # Проверяем, сколько вернулось позиций в snmp ответа для корректировки сдвига на некоторых моделях
        if len(result) % 3 == 0:
            i = -1
        else:
            i = 0

        # Определяем количество портов и вносим поправку, если необходимо
        ports = int((len(result) - 3 - i)  / 3)

        # Для ME моделей
        # ports - 4 для пропуска uplink-ов
        if model in teln:
            res_change = set_LBD_telnet(ip, ports)
            print('change successfull, save successfull!' if res_change == 'Success' else 'что-то пошло не так')
            return

        # Условие для глобального включения LBD:
        # Сейчас LBD выключен или время восстановления меньше 1000 секунд
        if result[0] != '1' or int(result[3 + i]) <= 1000:
            res_change = set_LBD_global_snmp(ip, oid_LBD, 4 + i)
            print('change successfull' if not res_change else f'{res_change}', end=', ')

        # Идём по списку портов и настраиваем
        for port in range(1, ports + 1):

            # Условие для включения LBD на порту
            # Если LBD выключен и порт не аплинк
            if result[ports + 3 + i + port] != '1': # and (ports - port) >= 4:
                res = set_LBD_port_snmp(ip, oid_LBD, port, diff)
                if str(res) == 'badValue':
                    print(f"broken switch", end=', ')
                    break

        # Сохраняем изменения
        res_save = save_config_snmp(ip, oid_save)
        print('save successfull!' if not res_save else f'{res_save}')

    except:
        print(f"Error on host {ip} {model}")


def get_storm_snmp(ip, oid, com_data=SNMP_PUBLIC):

    """
    Проверка настроек storm control всех портов на D-Link не ME. Принимает ip хоста и oid.
    Возвращает список с состоянием storm control и количеством разрешённых хостов
    """

    # Переменная для возвращения результатов и индекс вложенного списка
    result = []
    i = 0

    # Подключаемся к хосту и получаем snmp ответ
    for (errorIndication,
         errorStatus,
         errorIndex,
        varBinds) in nextCmd(SnmpEngine(),
                          CommunityData(com_data),
                          UdpTransportTarget((ip, 161)),
                          ContextData(),
                          ObjectType(ObjectIdentity(oid))):

        # Выводим ошибку в случае отсутствия ответа от хоста
        if errorIndication or errorStatus:
            print(errorIndication or errorStatus)
            break

        else:

            for line in varBinds:

                # Конвертируем ответ в строку для работы с ним
                line = str(line)

                # Защита на случай, если пошли другие snmp с таким же форматом
                if oid[12:] not in line:
                    return result

                # Разделяем snmp ответ и записываем в список переменную с ответом
                result.append(line.split('=')[1][1:])

    # Возвращаем список с результатами
    return result


def get_storm_telnet(ip, user=USERNAME_DLINK, password=PASSWORD_DLINK_OLD):

    """
    Проверка настроек storm control на D-Link */ME. Принимает ip хоста, логин и пароль.
    Возвращает список строк или 'Fail' в зависимости от успеха.
    """

    try:
        port = '23'

        # Задаём команды для ввода
        command_1 = 'show traffic control'
        command_2 = 'n'

        # Пытаемся подключиться, все команды выполняем с таймаутом 5 сек
        tn = telnetlib.Telnet(ip, port, timeout=5)
        tn = telnetlib.Telnet(ip, timeout=5)

        # Вводим логин
        tn.read_until(b": ", timeout=3)
        tn.write(user.encode('UTF-8') + b"\n")

        # Вводим пароль
        tn.read_until(b"Password: ", timeout=3)
        tn.write(password.encode('UTF-8') + b"\n")

        # Вводим команду для вывода настроек storm control
        tn.read_until(b'#', timeout=3)
        tn.write(command_1.encode('UTF-8') + b"\r\n")

        # Сохраняем вывод в переменную и выводим следующую страницу
        line_1 = tn.read_until(b'ALL', timeout=3)
        tn.write(command_2.encode('UTF-8') + b"\r\n")

        # Сохраняем вывод в переменную и выводим следующую страницу
        line_2 = tn.read_until(b'ALL', timeout=3)
        tn.write(command_2.encode('UTF-8') + b"\r\n")

        # Сохраняем вывод в переменную и выводим следующую страницу
        line_3 = tn.read_until(b'ALL', timeout=3)
        tn.write(command_2.encode('UTF-8') + b"\r\n")

        # Сохраняем вывод в переменную и отключаемся
        line_4 = tn.read_until(b'#', timeout=5)
        tn.close()

        # Возвращаем результат в виде списка строк
        return str(line_1).split("\\r\\n") + str(line_2).split("\\r\\n") + str(line_3).split("\\r\\n") + str(line_4).split("\\r\\n")

    # Если в ходе проверки возникла какая-то ошибка, возвращаем 'Мёртв'
    except:
        return 'Fail'


def get_storm(ip, model, oid):

    """
    Вывод настроек storm control на длинках, принимает ip хоста, модель и oid.
    Выводит на экран настройки по списку хостов.
    """

    # Пробуем получить настройки port-security на хосте
    try:
        print('\nПодключаемся к хосту', model, ip, '\n')

        # Модели для работы по telnet
        teln = ['DES-1210-28 A1', 'DES-1210-28/ME A1', 'DES-1210-28/ME B2', 'DES-1210-28/ME B3']

        # Проверка, нужно ли настраивать оборудование через telnet
        if model in teln:

            # Если да - создаём список для хранения вывода
            result = []
            i = 0

            # Получаем в ответе из функции список со строками
            result_temp = get_storm_telnet(ip)

            # Проверяем каждую строку с удалёнными лишними символами на соответствие регулярному выражению
            for line in result_temp:
                match = re.search(' *(\d+) +(\d+) +(\S+) +(\S+) +(\S+) *', line.replace('\\r', '').replace('\\x1b', '').replace('[K', ''))

                # Если совпадение нашлось - проверяем, начинается ли оно с цифры (номера порта)
                if match:
                    if match.group(1).isdigit():

                        # Если да - создаём вложенный список и добавляем туда результаты из регулярного выражения
                        result.append([])
                        result[i].append(match.group(1))
                        result[i].append(match.group(2))
                        result[i].append(match.group(3))
                        result[i].append(match.group(4))
                        result[i].append(match.group(5))
                        i += 1

            # Проверяем число строк в ответе. Если их больше 60 - на каждый порт приходится три строки ответа
            if len(result) > 60:

                # Переменная для проверки, закончился ли вывод информации по порту
                temp_port = '1'

                # Отсчитывает, для какого трафика идёт вывод
                i = 0

                # Переменная для ограничения скорости потока
                thres = 0

                # Используется для разбора первый строки списка
                k = True

                # Для каждой строки проверяем, включена ли фильтрация и выводим текст в зависимости от ответа
                for res in result:

                    # Если переменная временного порта равна текущему порту -
                    # Продолжаем записывать во временные переменные настроки для потока
                    if temp_port == res[0]:

                        # Если ограничение потока на порту больше 0 - записываем его в переменную
                        if int(res[1]) > 0:
                            thres = res[1]

                        # Используется для записи параметра Broadcast для первой строки
                        if i == 0 and temp_port == '1' and k:
                            broad = res[3]
                            k = False
                            continue

                        # Если вход в эту ветку первый раз - это параметры для Multicast, записываем в переменную
                        if i == 0:
                            multi = res[3]

                        # Если второй раз - это параметры для Unicast, записываем в переменную
                        else:
                            uni = res[3]

                        # Добавляем к счётчику вхождений в ветку 1
                        i += 1

                    # Если переменная временного порта не равна текущему номеру порта - выводим результаты на порту
                    else:
                        print(f"На порту {temp_port} ограничение в {thres} Kbps, "
                              f"Broadcast - {'включен' if broad == 'Enabled' else 'выключен'}, Multicast - "
                              f"{'включен' if multi == 'Enabled' else 'выключен'}, Unknown Unicast - "
                              f"{'включен' if uni == 'Enabled' else 'выключен'}")

                        # Присваиваем текущий номер порта, ограничение скорости потока и
                        # параметры Broadcast трафика в переменную, сбрасываем счётчик на ноль
                        temp_port = res[0]
                        thres = res[1]
                        broad = res[3]
                        i = 0

                # Вывод параметров для последнего порта
                print(f"На порту {temp_port} ограничение в {thres} Kbps, "
                      f"Broadcast - {'включен' if broad == 'Enabled' else 'выключен'}, Multicast - "
                      f"{'включен' if multi == 'Enabled' else 'выключен'}, Unknown Unicast - "
                      f"{'включен' if uni == 'Enabled' else 'выключен'}")

                return

            # Если число строк меньше 60 - выводим ответ в таком формате
            else:

                for res in result:
                    print(f"На порту {res[0]} ограничение в {res[1]} Kbps, Broadcast - "
                          f"{'включен' if res[2] == 'Enabled' else 'выключен'}, Multicast - "
                          f"{'включен' if res[3] == 'Enabled' else 'выключен'}, Unknown Unicast - "
                          f"{'включен' if res[4] == 'Enabled' else 'выключен'}")

                return

        # Подключаемся к функции и забираем данные в список
        result = get_storm_snmp(ip, oid)

        # Проверяем, какой трафик фильтруется на порту
        if result[1] == '1':
            pack = 'Broadcast'
        elif result[1] == '2':
            pack = 'Broadcast and Multicast'
        else:
            pack = 'Broadcast, Multicast and Unknown Unicast'

        # Выводим общую информацию по LBD на устройстве
        print(f"На устройстве {'включен' if result[0] == '1' else 'выключен'} Storm Control для трафика "
              f"{pack} и максимум {result[2]} Kbps\n")

    except:
        print('Error')
        pass


def set_storm_snmp(ip, oid, size=384, state=1, who=3, com_data=SNMP_PRIVATE):

    """
    Настройка storm control на D-Link не ME, принимает ip хоста, oid, размер шторма, состояние, типы пакетов для мониторинга.
    Может вернуть ошибку
    """

    # Подключаемся к хосту и получаем snmp ответ
    for (errorIndication,
         errorStatus,
         errorIndex,
         varBinds) in setCmd(SnmpEngine(),
                          CommunityData(com_data),
                          UdpTransportTarget((ip, 161), timeout=5, retries=3),
                          ContextData(),
                          ObjectType(ObjectIdentity(f'{oid}.1.0'), Integer32(state)),   # Включение\отключение storm control
                          ObjectType(ObjectIdentity(f'{oid}.2.0'), Integer32(who)),     # Какие типы пакетов мониторить
                          ObjectType(ObjectIdentity(f'{oid}.3.0'), Integer32(size))):   # Размер шторма

        # Возвращаем ошибку в случае отсутствия ответа от хоста
        if errorIndication or errorStatus:
            return errorIndication or errorStatus


def set_storm_telnet(ip, user=USERNAME_DLINK, password=PASSWORD_DLINK_OLD):

    """
    Настройка storm control на D-Link */ME, принимает ip хоста, логин и пароль.
    Возвращает 'Success' или 'Fail' в зависимости от успеха.
    """

    try:
        port = '23'

        # Задаём команды для ввода, все варианты для разных моделей
        commands = ['config traffic control all action drop threshold 384 broadcast enable',
                    'config traffic control all action drop threshold 384 multicast enable',
                    'config traffic control all action drop threshold 384 unicast enable',
                    'config traffic control all broadcast enable multicast enable unicast enable threshold 384',
                    'save',
                    ]

        # Пытаемся подключиться, все команды выполняем с таймаутом 5 сек
        tn = telnetlib.Telnet(ip, port, timeout=5)
        tn = telnetlib.Telnet(ip, timeout=5)

        # Вводим логин
        tn.read_until(b": ", timeout=5)
        tn.write(user.encode('UTF-8') + b"\n")

        # Вводим пароль
        tn.read_until(b"Password: ", timeout=5)
        tn.write(password.encode('UTF-8') + b"\n")

        # Идём по списку команд
        for command in commands:
            tn.read_until(b'#', timeout=5)
            tn.write(command.encode('UTF-8') + b"\r\n")

        tn.read_until(b'#', timeout=10)
        tn.close()

        return 'Success'

    # Если в ходе проверки возникла какая-то ошибка, возвращаем 'Мёртв'
    except:
        return 'Fail'


def set_storm(ip, model, oid_storm, oid_save):

    """
    Настройка Storm Control, принимает ip хоста, модель, oid для storm control и сохранения конфига.
    Возвращает вывод на экран или ошибку
    """

    try:
        print(model, ip, end=', ')

        # Модели для работы по telnet
        teln = ['DES-1210-28 A1', 'DES-1210-28/ME A1', 'DES-1210-28/ME B2', 'DES-1210-28/ME B3']

        # Для ME моделей
        if model in teln:
            res_change = set_storm_telnet(ip)
            print('change successfull, save successfull!' if res_change == 'Success' else 'что-то пошло не так')
            return

        # Для модели с другим рассчётом величины пакетов
        if model == 'DES-1210-28 BX':
            res_change = set_storm_snmp(ip, oid_storm, size=378)

        else:
            # Для остальных моделей
            res_change = set_storm_snmp(ip, oid_storm)

        print('change successfull' if not res_change else f'{res_change}', end=', ')

        # Сохраняем изменения
        res_save = save_config_snmp(ip, oid_save)
        print('save successfull!' if not res_save else f'{res_save}')

    except:
        print('\nError')
        return


def get_stp_snmp(ip, oid, com_data=SNMP_PUBLIC):

    """
    Чтение состояния STP, принимает ip хоста и oid.
    Возвращает 'Включен' либо 'Выключен'.
    """

    # Подключаемся к хосту и получаем snmp ответ
    for (errorIndication,
         errorStatus,
         errorIndex,
        varBinds) in getCmd(SnmpEngine(),
                          CommunityData(com_data),
                          UdpTransportTarget((ip, 161)),
                          ContextData(),
                          ObjectType(ObjectIdentity(f"{oid}"))):

        # Выводим ошибку в случае отсутствия ответа от хоста
        if errorIndication or errorStatus:
            return errorIndication or errorStatus
            break

        else:

            for line in varBinds:

                # Возвращаем результат
                return 'Включен' if str(line).split('=')[1] == ' 1' else 'Выключен'


def set_stp_snmp(ip, oid, state=2, com_data=SNMP_PRIVATE):

    """
    Изменение глобального параметра STP, принимает ip хоста, oid и состояние.
    Может вернуть ошибку
    """

    # Подключаемся к хосту и получаем snmp ответ
    for (errorIndication,
         errorStatus,
         errorIndex,
         varBinds) in setCmd(SnmpEngine(),
                          CommunityData(com_data),
                          UdpTransportTarget((ip, 161), timeout=5, retries=3),
                          ContextData(),
                          ObjectType(ObjectIdentity(oid), Integer32(state))):   # 1 - включение, 2 - отключение STP

        # Возвращаем ошибку в случае отсутствия ответа от хоста
        if errorIndication or errorStatus:
            return errorIndication or errorStatus


def get_mac_snmp_to_sql(ip, model, com_data=SNMP_PUBLIC):

    """
    Чтение мак-адресов с длинков и запись их в базу, принимает ip хоста и модель.
    Может вернуть ошибку.
    """

    # Список с результатами
    result = []

    # Определяем, какие порты у модели аплинки
    if '52' in model:
        uplink = 48
    elif '28' in model:
        uplink = 24
    elif 'DGS-1210-10P' in model:
        uplink = 8

    # Подключаемся к хосту и получаем snmp ответ
    for (errorIndication,
         errorStatus,
         errorIndex,
        varBinds) in nextCmd(SnmpEngine(),
                          CommunityData(com_data),
                          UdpTransportTarget((ip, 161)),
                          ContextData(),
                          ObjectType(ObjectIdentity(f'.1.3.6.1.2.1.17.7.1.2.2.1.2'))):

        # Выводим ошибку в случае чего
        if errorIndication or errorStatus:
            return errorIndication or errorStatus
            break

        else:

                for line in varBinds:

                    # Конвертируем ответ в строку для работы с ним
                    line = str(line)

                    # Проверяем, понимает ли устройство этот OID
                    if 'No Such' in line:
                        print(f'Для хоста не подходит OID')
                        return

                    # Проверяем, не закончилась ли выдача по указанному OID-у
                    elif '17.7.1.2.2.1.2' not in line:

                        # Если закончилась - подключаемся к базе
                        cursor = connect_to_DB()

                        # Идём по списку пользователей, найденных на длинке
                        for res in result:

                            # Проверяем, существует ли мак адрес в базе
                            history = get_users(cursor, res[0])
                            # Если существует - получаем ответ вида [ [ip адрес, порт, влан], ...]

                            # Если пользователь не нашёлся в базе - записываем его
                            if not history:
                                users_to_sql(cursor, ip, res[0], res[1], res[2])

                            # Если пользователь есть - проверяем, поменялось ли устройство, порт или влан
                            else:

                                # Если что-либо поменялось - обновляем запись в базе
                                if (ip != history[0][0]) or (int(res[1]) != int(history[0][1])) or (int(res[2]) != int(history[0][2])):
                                    users_to_sql(cursor, ip, res[0], res[1], res[2])

                        # Закрываем подключение к базе
                        cursor.close()

                        return

                    # Разделяем snmp ответ для обработки и задаём последнюю часть для обработки
                    line = line.split('.')
                    last = line[14].split()

                    # Присваиваем значение порту и проверяем, не является ли он аплинком
                    port = last[2]
                    if int(port) > uplink:
                        continue
                    
                    # Присваиваем значения остальным переменным
                    vlan = line[8]
                    mac_temp = line[9:14]
                    mac_temp.append(last[0])

                    # Список для временного хранения результата
                    parts = []

                    # Конвертируем мак (изначально он в десятичном формате) и заносим в список
                    for number in mac_temp:
                        parts.append('{0:02x}'.format(int(number)))

                    # Создаём переменную для стандартного вывода мака
                    mac = ':'.join([x for x in parts])
                    mac = mac.upper()

                    # Добавляем результаты в список и увеличиваем счётчик
                    result.append([mac, port, vlan])


def get_vlan_snmp(ip, model, oid, com_data=SNMP_PUBLIC):

    """
    Получения настроек vlan-a с D-Link-а, принимает ip хоста, модель и oid.
    Возвращает список или ошибку.
    """

    # Создаём переменные для кучи разных проверок
    check = False
    result = []
    temp_array_ports = []
    temp_index = []
    temp_check = False
    temp_array = []
    temp_state_array = []
    check_name = False
    check_state = False

    # Подключаемся к хосту и получаем snmp ответ
    for (errorIndication,
         errorStatus,
         errorIndex,
        varBinds) in nextCmd(SnmpEngine(),
                          CommunityData(com_data),
                          UdpTransportTarget((ip, 161)),
                          ContextData(),
                          ObjectType(ObjectIdentity(oid))):

        # Выводим ошибку в случае чего
        if errorIndication or errorStatus:
            print(errorIndication or errorStatus)
            break

        else:

            for line in varBinds:

                # Конвертируем ответ в строку для работы с ним
                line = str(line)

                if oid[12:] not in line:
                    check = True
                    break

                try:
                    # Проверяем, если первым ответом идёт индекс сети - пропускаем его
                    if line.split()[2].isdigit() and line.split()[0].split('.')[-2] == '1':
                        check_name = True
                        continue

                    # Проверяем, появился ли строке ответ о состоянии портов
                    if line.split()[2].startswith('0x'):
                    
                        # Если да, и индекс ответа не во временном списке индексов - добавляем его
                        if line.split()[0].split('.')[-2] not in temp_index:
                            temp_index.append(line.split()[0].split('.')[-2])
                        
                        # Так же добавляем ответ во временный список с ответами и меняем состояние переключателя
                        temp_array_ports.append(line.split()[2])
                        temp_check = True
                        continue

                    # Если переключатель включён и в строке уже нет ответов о состоянии порта
                    if temp_check and not line.split()[2].startswith('0x'):
                    
                        # Если в ответе было всего два индекса - всё отлично, записываем временный список с ответами в настоящий результат
                        if len(temp_index) == 2:
                            vlans = int(len(temp_array_ports)/2)
                            for temp_line in temp_array_ports:
                                result.append(temp_line)
                        
                        # Если же нет - добавляем сначала ответы с первым индексом, а потом с третьим, пропуская бесполезный второй
                        else:
                            vlans = int(len(temp_array_ports)/3)
                            temp = int(len(temp_array_ports) / len(temp_index))
                            for temp_line in range(temp):
                                result.append(temp_array_ports[temp_line])
                            for temp_line in range(temp * 2, temp * 3):
                                result.append(temp_array_ports[temp_line])
                        temp_check = False
                        check_state = True

                    # Проверяем, закончилась ли выдача настроек портов и если да - записываем остальное во временнный массив
                    if check_state:
                        temp_state_array.append(line.split()[2])
                        continue

                    # Если же идут обычные данные - добавляем их
                    result.append(line.split()[2])

                # На случай, если приходит пустой ответ, обычно для имени первого влана, записываем его как default
                except IndexError:
                    result.append('default')

                # Проверка, является ли единица предпоследним октетом, и если да - добавляем последний октет, номер влана
                if line.split()[0].split('.')[-2] == '1':
                    result.append(line.split()[0].split('.')[-1])
                    continue

                # Аналогичная проверка, только уже с двойкой, для длинков, у которых на единицу приходится просто номер влана
                if line.split()[0].split('.')[-2] == '2' and check_name == True:
                    result.append(line.split()[0].split('.')[-1])
                    continue

            # Если в снмп пошли другие ответы - записываем из временного ответа в результат состояние вланов
            if check:
                
                # Если в ответе только состояние влана - просто записываем его в результат
                if len(temp_state_array) == vlans:
                    for temp in range(vlans):
                        result.append(temp_state_array[temp])
                
                # Если там ещё настройки рассылки состояния - пропускаем их и записываем только состояние влана
                else:
                    for temp in range(vlans):
                        result.append(temp_state_array[vlans+temp])
                
                break
    return result


def get_vlan(ip, model, oid):

    """
    Получение и форматирование настроек vlan-a с D-Link-а, принимает ip хоста, модель и oid.
    Возвращает список вида [['имя влана', 'номер влана', 'состояние портов', 'состояние влана',], ...] и выводит его на экран.
    """

    result = []
    g = -1

    try:

        # Смотрим количество портов в модели
        if '52' in model:
            ports = 52
        elif '28' in model:
            ports = 28

        # Получаем список из функции
        res = get_vlan_snmp(ip, model, oid)

        # считаем количество vlan в ответе
        vlan = int(len(res) / 5)

        # Идём в цикле по количеству вланов
        for i in range(vlan):

            # Переменная для хранения состояние тэгов
            tag = ''
            g += 1
            result.append([])

            # Забираем информацию с именем и номером влана
            result[g].append(res[2*i])
            result[g].append(res[2*i+1])

            # Присваиваем переменной значение якобы тэгированного влана
            fake_tag = res[i+vlan*2]
            all_tag = ''

            # Переводим значение тэгированных портов в 0 и 1
            for port in range(1, int(ports / 4) + 1):
                all_tag += f"{int(fake_tag[1 + port], 16):04b}"

            # Присваиваем переменной значение не тэгированного влана
            untagged = res[i+vlan*3]
            all_untag = ''

            # Переводим значение тэгированных портов в 0 и 1
            for port in range(1, int(ports / 4) + 1):
                all_untag += f"{int(untagged[1 + port], 16):04b}"

            # Высчитываем, какие порты действительно тэгированные и переводим в двоичный вид
            real_tag = int(all_tag, 2) - int(all_untag, 2)
            real_tag = f"{real_tag:0{ports}b}"

            space = 0
            # Присваиваем переменной 2 за тег, 1 за нетег, 0 за отсутствие влана на порту
            # Так же добавляем пробел после каждого четвёртого порта для удобочитаемости
            for k in range(len(all_untag)):
                if real_tag[k] == '1':
                    if space == 4:
                        tag += ' 2'
                        space = 0
                    else:
                        tag += '2'
                elif all_untag[k] == '1':
                    if space == 4:
                        tag += ' 1'
                        space = 0
                    else:
                        tag += '1'
                else:
                    if space == 4:
                        tag += ' 0'
                        space = 0
                    else:
                        tag += '0'
                space += 1

            # Забираем состояния vlan и на какие порты он назначен
            result[g].append(tag)
            result[g].append(res[-(vlan-i)])

        return result

    except IndexError:
        print(f"\nЭтот убогий {ip} {model} опять сломался")
        return False
    except ValueError:
        print(f"\nЭтот убогий {ip} {model} опять сломался")
        return False
    except:
        return False


def get_mac_snmp(ip, com_data=SNMP_PUBLIC):

    """
    Получение мак адреса dlink-а, принимает ip хоста.
    Возвращает мак адрес или ошибку.
    """

    # Переменная для хранения результата
    res = ''

    # Подключаемся к хосту и получаем snmp ответ
    for (errorIndication,
         errorStatus,
         errorIndex,
        varBinds) in getCmd(SnmpEngine(),
                          CommunityData(com_data),
                          UdpTransportTarget((ip, 161)),
                          ContextData(),
                          ObjectType(ObjectIdentity(".1.3.6.1.2.1.17.1.1.0"))):

        # Выводим ошибку в случае отсутствия ответа от хоста
        if errorIndication or errorStatus:
            return errorIndication or errorStatus
            break

        else:

            for line in varBinds:

                # Отбрасываем лишние части в ответе
                result = str(line).split(' ')[2][2:]
                
                # Переводим ответ в обычный вид типа XX:XX:XX...
                for i in range(12):

                    # Вставляем после каждого второго символа ':'
                    if i % 2:
                        res += result[i] + ':'
                    else:
                        res += result[i]

                # Возвращаем результат
                return res[:-1].upper()


def check_dlink_office(ip, dlinks):

    """
    Обновление\добавление записей офисных длинков в базу, принимает ip хоста.
    Возвращает False или True в зависимости от результата
    """

    # Флаг для проверки изменения данных
    change = False

    # Получаем модель и версию хардвары, мак адрес
    model, firmware = get_object_snmp(ip)
    m_f = model + ' ' + firmware
    mac = get_mac_snmp(ip)

    # Если что-либо из этого обработалось неправильно - выводим ошибку и выходим из функции
    if 'error' in m_f:
        return False

    # Пропускаем HP и 3Com
    elif 'HP' in m_f or 'ProCurve' in m_f or '3Com' in m_f:
        return False

    # В противном случае проверяем, есть ли устройство с таким адресом в базе
    else:

        for dlink in dlinks:

            # Если существует - проверяем, не изменился ли мак адрес и модель
            if ip == dlink[1]:
                if mac == dlink[2]:
                    if m_f == dlink[0]:

                        # Если ничего не изменилось - выходим из функции
                        return

                    else:
                        change = True
                else:
                    change = True

        # Если добрались сюда - устройства или нет в базе, или оно изменилось
        # Проверяем состояние флага, если он True - обновляем запись в базе
        if change:

            dlink_office_to_sql(ip, mac, m_f, 'UPDATE')

        # В противном случае - добавляем устройство в базу
        else:

            dlink_office_to_sql(ip, mac, m_f, 'INSERT')

    return True


def get_mac_port_dlink(ip, mac, com_data=SNMP_PUBLIC):

    """
    Поиск мак-адреса в 1 vlan-е на dlink-е, принимает ip хоста и мак адрес.
    Возвращает [ip, port] или ничего, в зависимости от успеха
    """

    # Создаём переменную для выхода из цикла и хранения результата
    check = False
    result = []

    # Подключаемся к хосту и получаем snmp ответ
    for (errorIndication,
         errorStatus,
         errorIndex,
        varBinds) in getCmd(SnmpEngine(),
                          CommunityData(com_data),
                          UdpTransportTarget((ip, 161)),
                          ContextData(),
                          ObjectType(ObjectIdentity(f'.1.3.6.1.2.1.17.7.1.2.2.1.2.1.{mac}'))):

        # Выводим ошибку в случае чего
        if errorIndication or errorStatus:
            print(f"Host {ip} ", errorIndication or errorStatus)
            return

        else:

            # Try на случай ошибок в ходе получения ответа
            try:

                for line in varBinds:

                    # Конвертируем ответ в строку для работы с ним
                    line = str(line)

                    # Возвращаем ничего, если мак-адрес отстутствует
                    if 'No Such' in line:
                        return

                    # Разделяем snmp ответ для обработки и задаём последнюю часть для обработки
                    varBind = line.split('.')
                    last = varBind[14].split()

                    # Присваиваем переменной последнюю часть с номером порта
                    port = last[2]

                    result.append(ip)
                    result.append(port)

            except IndexError:
                check = True
        if check:
            break

    return result


def ping_from_dlink(ip, model, pings, user=USERNAME_DLINK, password=PASSWORD_DLINK_OLD):

    """
    Запуск пингов с длинка для появления мака в списке адресов, принимает ip хоста, модель и список адресов для пинга.
    Возвращает 'Fail' или 'Success' в зависимости от успеха
    """

    try:

        port = '23'

        # Пытаемся подключиться, все команды выполняем с таймаутом 5 сек
        tn = telnetlib.Telnet(ip, port, timeout=5)
        tn = telnetlib.Telnet(ip, timeout=5)

        # Вводим логин
        tn.read_until(b": ", timeout=5)
        tn.write(user.encode('UTF-8') + b"\n")

        # Вводим пароль
        tn.read_until(b"word: ", timeout=5)
        tn.write(password.encode('UTF-8') + b"\n")

        # Ветка для модели D-Link */ME
        if 'ME' in model:

            # Идём по списку адресов для пинга
            for ping in pings:

                # Если адрес равен своему - пропускаем его
                if ip == ping:
                    continue

                # Отправляем команду для пинга
                tn.read_until(b'#', timeout=30)
                tn.write(f"ping {ping}".encode('UTF-8') + b"\r\n")

            # Ждём окончания пингов
            tn.read_until(b'#', timeout=30)

        # Ветка для остальных моделей Dlink-а
        else:

            # Идём по списку адресов для пинга
            for ping in pings:

                # Если адрес равен своему - пропускаем его
                if ip == ping:
                    continue

                # Отправляем команду для пинга
                tn.read_until(b'>', timeout=30)
                tn.write(f"ping {ping}".encode('UTF-8') + b"\r\n")

            # Ждём окончания пингов
            tn.read_until(b'>', timeout=30)
        
        # Закрываем соединение
        tn.close()

        return 'Success'

    # Если в ходе проверки возникла какая-то ошибка, возвращаем 'Fail'
    except:
        print(f"Ошибка на хосте {ip}")
        return 'Fail'


def set_logs_snmp(ip, oid, server, severity=7, timestamp=2, port=514, state=1, facility=128, com_data=SNMP_PRIVATE):

    """
    Настрока логирования на длинках. Принимает ip хоста, oid, ip сервера, уровень логирования,
    временная отметка, порт и состояние.
    Возвращает ошибку или False в зависимости от результата.
    """

    # Задаём параметры для логирования
    for (errorIndication,
         errorStatus,
         errorIndex,
         varBinds) in setCmd(SnmpEngine(),
                          CommunityData(com_data),
                          UdpTransportTarget((ip, 161), timeout=5, retries=3),
                          ContextData(),
                          ObjectType(ObjectIdentity(f'{oid}.1.0'), IpAddress(server)),      # Сервер куда будут падать логи
                          ObjectType(ObjectIdentity(f'{oid}.2.0'), Integer32(port)),        # Номер порта
                          ObjectType(ObjectIdentity(f'{oid}.3.0'), Integer32(timestamp)),   # Показывать или нет время в логе. 2 - нет, 1 - да
                          ObjectType(ObjectIdentity(f'{oid}.4.0'), Integer32(severity)),    # Уровень мониторинга. 4- warning, 7 - all
                          ObjectType(ObjectIdentity(f'{oid}.5.0'), Integer32(facility))):   # Непонятная фигня, лучше оставлять как есть

        # Выполняем snmp команды
        pass

    # Включаем логирование
    for (errorIndication,
         errorStatus,
         errorIndex,
         varBinds) in setCmd(SnmpEngine(),
                          CommunityData(com_data),
                          UdpTransportTarget((ip, 161), timeout=5, retries=3),
                          ContextData(),
                          ObjectType(ObjectIdentity(f'{oid}.6.0'), Integer32(state))):   # Состояние логирования. 1 - вкл, 2 - выкл

        # Возвращаем ошибку в случае отсутствия ответа от хоста
        if errorIndication or errorStatus:
            return errorIndication or errorStatus

    # Возвращаем False если всё хорошо
    return False


def set_logs_telnet(ip, server, user=USERNAME_DLINK, password=PASSWORD_DLINK_OLD, severity='all', udp_port=514, facility='local0', state='enable'):

    """
    Настрока логирования на длинках ME. Принимает ip хоста, ip сервера, логин, пароль, уровень логирования, порт и состояние.
    Может вернуть False или True в зависимости от результата.
    """

    try:
        port = '23'

        # Задаём команды для ввода, для создания или изменения существующего сервера
        commands = ['enable syslog',
                    f'create syslog host 1 ipaddress {server} facility {facility} severity {severity} state {state} udp_port {udp_port}',
                    f'config syslog host 1 ipaddress {server} facility {facility} severity {severity} state {state} udp_port {udp_port}',
                    'save',
                    ]

        # Пытаемся подключиться, все команды выполняем с таймаутом 5 сек
        tn = telnetlib.Telnet(ip, port, timeout=5)
        tn = telnetlib.Telnet(ip, timeout=5)

        # Вводим логин
        tn.read_until(b": ", timeout=5)
        tn.write(user.encode('UTF-8') + b"\n")

        # Вводим пароль
        tn.read_until(b"Password: ", timeout=5)
        tn.write(password.encode('UTF-8') + b"\n")

        # Идём по списку команд
        for command in commands:
            tn.read_until(b'#', timeout=5)
            tn.write(command.encode('UTF-8') + b"\r\n")

        tn.read_until(b'#', timeout=10)
        tn.close()

        return True

    # Если в ходе проверки возникла какая-то ошибка, возвращаем 'Мёртв'
    except:
        return False


def set_logs(ip, model, subnet, oid_logs, oid_save):

    """
    Изменяем настройки логов на длинках. Принимает ip хоста, модель, подсеть, oid для логов и сохранения конфига.
    Возвращает True или False в зависимости от успеха, так же выводим информацию текстом.
    """

    try:

        # Модели для работы по telnet
        teln = ['DES-1210-28 A1', 'DES-1210-28/ME A1', 'DES-1210-28/ME B2', 'DES-1210-28/ME B3']

        # Модели без полноценной возможности настройки snmp
        no_logs = ['DGS-1210-52 FX', 'DGS-1210-28 FX', 'DES-1210-52 CX']

        # Для ME моделей
        if model in teln:
            res_change = set_logs_telnet(ip, f'{subnet}.100')
            print(model, ip, 'change successfull, save successfull!' if res_change == True else 'что-то пошло не так')
            return True

        # Для модели с другим рассчётом величины пакетов
        elif model in no_logs:
            print(model, ip, 'для них нет возможности настроить log сервер скриптом')
            return True

        else:
            # Для остальных моделей
            res_change = set_logs_snmp(ip, oid_logs, f'{subnet}.100')

        print(model, ip, 'change successfull' if not res_change else f'{res_change}', end=', ')

        # Сохраняем изменения
        res_save = save_config_snmp(ip, oid_save)
        print('save successfull!' if not res_save else f'{res_save}')

        return True

    except:
        print('\nError')
        return False


def set_sntp_snmp(ip, oid, model, server='172.29.0.10', state=1, time=3600, ip_vers=1, com_data=SNMP_PRIVATE):

    """
    Настрока sntp на длинках. Принимает ip хоста, oid, модель, ip сервера, состояние, время между запросами, версию ip сервера.
    Возвращает ошибку или False в зависимости от результата.
    """

    # Модели с кривым sntp
    bad_models = ['DGS-1210-52 FX', 'DGS-1210-28 FX', 'DES-1210-52 CX']

    # Проверяем модель dlink-а:
    if model in bad_models:

        ip_xvi = ''
        for i in server.split('.'):
            ip_xvi +=  '{0:02x}'.format(int(i))

        # Задаём параметры для логирования
        for (errorIndication,
             errorStatus,
             errorIndex,
             varBinds) in setCmd(SnmpEngine(),
                              CommunityData(com_data),
                              UdpTransportTarget((ip, 161), timeout=5, retries=3),
                              ContextData(),
                              ObjectType(ObjectIdentity(f'{oid}.2.0'), OctetString(hexValue=ip_xvi)),    # IP сервера времени в 16-ричной системе
                              ObjectType(ObjectIdentity(f'{oid}.3.0'), Integer32(ip_vers)),     # Версия IP протокола, 1 - ipv4, 2 - ipv6
                              ObjectType(ObjectIdentity(f'{oid}.8.0'), Integer32(time)),        # Раз во сколько секунд обращаться
                              ObjectType(ObjectIdentity(f'{oid}.9.0'), Integer32(state))):      # Метод, 1 - sntp, 2 - local

            # Выполняем snmp команды
            if errorIndication or errorStatus:
                return errorIndication or errorStatus

    else:

        # Задаём параметры для логирования
        for (errorIndication,
             errorStatus,
             errorIndex,
             varBinds) in setCmd(SnmpEngine(),
                              CommunityData(com_data),
                              UdpTransportTarget((ip, 161), timeout=5, retries=3),
                              ContextData(),
                              ObjectType(ObjectIdentity(f'{oid}.2.0'), IpAddress(server)),      # Сервер времени
                              ObjectType(ObjectIdentity(f'{oid}.4.0'), Integer32(time)),        # Раз во сколько секунд обращаться
                              ObjectType(ObjectIdentity(f'{oid}.5.0'), Integer32(state))):      # Метод, 1 - sntp, 2 - local

            # Выполняем snmp команды
            if errorIndication or errorStatus:
                return errorIndication or errorStatus

    # Возвращаем False если всё хорошо
    return False


def set_sntp(ip, model, oid_sntp, oid_save, server='172.29.0.10'):

    """
    Изменяем настройки sntp на длинках. Принимает ip хоста, модель, oid для логов и сохранения конфига, ip сервера.
    Возвращает True или False в зависимости от успеха, так же выводим информацию текстом.
    """

    try:

        res_change = set_sntp_snmp(ip, oid_sntp, model)

        print(model, ip, 'change successfull' if not res_change else f'{res_change}', end=', ')

        # Сохраняем изменения
        res_save = save_config_snmp(ip, oid_save)
        print('save successfull!' if not res_save else f'{res_save}')

        return True

    except:
        print('\nError')
        return False


def set_tag_vlan_snmp(ip, oid, vlan_id, ports, mod='2', com_data=SNMP_PRIVATE):

    for (errorIndication,
    errorStatus,
    errorIndex,
    varBinds) in setCmd(SnmpEngine(),
                            CommunityData(com_data),
                            UdpTransportTarget((ip, 161), timeout=5, retries=3),
                            ContextData(),
                            ObjectType(ObjectIdentity(f"{oid}.1.{mod}.{vlan_id}"), OctetString(hexValue=ports))): # Задаём тэг порты

       return errorIndication or errorStatus


def set_untag_vlan_snmp(ip, oid, vlan_id, ports, mod='4', com_data=SNMP_PRIVATE):

    for (errorIndication,
    errorStatus,
    errorIndex,
    varBinds) in setCmd(SnmpEngine(),
                            CommunityData(com_data),
                            UdpTransportTarget((ip, 161), timeout=5, retries=3),
                            ContextData(),
                            ObjectType(ObjectIdentity(f"{oid}.1.{mod}.{vlan_id}"), OctetString(hexValue=ports))): # Задаём антэг порты

        return errorIndication or errorStatus


def set_del_vlan_snmp(ip, oid, vlan_id, com_data=SNMP_PRIVATE):

    next(setCmd(SnmpEngine(),
                CommunityData(com_data),
                UdpTransportTarget((ip, 161), timeout=5, retries=3),
                ContextData(),
                ObjectType(ObjectIdentity(f"{oid}.1.5.{vlan_id}"), Integer(6))))


def set_create_vlan_snmp(ip, model, oid, vlan_id, vlan_name='test', com_data=SNMP_PRIVATE):

    """
    Создаём влан и раскидываем на аплинки тэг, принимает ip хоста, модель, oid vlan-а, vlan id и vlan name.
    Возвращает False при успехе или текст с ошибкой
    """

    # Список для хранения ошибок
    errors = []

    # В зависимости от модели назначаем разные цифры для oid
    if model == 'DES-1210-28 A1':
        oids = (6, 1)
    else:
        oids = (5, 1)

    for (errorIndication,
        errorStatus,
        errorIndex,
        varBinds) in setCmd(SnmpEngine(),
                        CommunityData(com_data),
                        UdpTransportTarget((ip, 161), timeout=5, retries=3),
                        ContextData(),
                        ObjectType(ObjectIdentity(f"{oid}.1.{oids[0]}.{vlan_id}"), Integer(5))):            # Создаём влан

        if errorIndex or errorStatus:
            errors.append(f"Ошибка при создании vlan {errorIndication or errorStatus} на {ip} {model}")

    for (errorIndication,
        errorStatus,
        errorIndex,
        varBinds) in setCmd(SnmpEngine(),
                        CommunityData(com_data),
                        UdpTransportTarget((ip, 161), timeout=5, retries=3),
                        ContextData(),
                        ObjectType(ObjectIdentity(f"{oid}.1.{oids[1]}.{vlan_id}"), OctetString(vlan_name))):# Задаём имя влан

        if errorIndex or errorStatus:
            errors.append(f"Ошибка при назначении имени vlan {errorIndication or errorStatus} на {ip} {model}")

    for (errorIndication,
        errorStatus,
        errorIndex,
        varBinds) in setCmd(SnmpEngine(),
                        CommunityData(com_data),
                        UdpTransportTarget((ip, 161), timeout=5, retries=3),
                        ContextData(), 
                        ObjectType(ObjectIdentity(f"{oid}.1.{oids[0]}.{vlan_id}"), Integer(1))):            # Активируем влан

        if errorIndex or errorStatus:
            errors.append(f"Ошибка при активации vlan {errorIndication or errorStatus or errorIndex} на {ip} {model}")
            return errors

    # Возвращаем False если всё хорошо
    return False


def set_create_vlan_telnet(ip, vlan_id, vlan_name='test', user=USERNAME_DLINK, password=PASSWORD_DLINK_OLD):

    """
    Создание влана на Dlink */ME. Принимает ip хоста, vlan id, vlan name, логин и пароль.
    Возвращает True.
    """

    try:
        port = '23'

        # Задаём команды для ввода, для создания или изменения существующего сервера
        commands = [f'create vlan vlanid {vlan_id}',
                    f'config vlan vlanid {vlan_id} name {vlan_name} ',
                    'save',
                    ]

        # Пытаемся подключиться, все команды выполняем с таймаутом 5 сек
        tn = telnetlib.Telnet(ip, port, timeout=5)
        tn = telnetlib.Telnet(ip, timeout=5)

        # Вводим логин
        tn.read_until(b": ", timeout=5)
        tn.write(user.encode('UTF-8') + b"\n")

        # Вводим пароль
        tn.read_until(b"Password: ", timeout=5)
        tn.write(password.encode('UTF-8') + b"\n")

        # Идём по списку команд
        for command in commands:
            tn.read_until(b'#', timeout=5)
            tn.write(command.encode('UTF-8') + b"\r\n")

        # Считывает последний ответ и конвертируем в строку
        result = str(tn.read_until(b'#', timeout=5))
        print(result)
        #tn.read_until(b'#', timeout=10)
        tn.close()
        if 'assword' in result:
            set_create_vlan_telnet(ip, vlan_id, vlan_name='test', user=USERNAME_DLINK, password=PASSWORD_DLINK_NEW)


    except:
        pass

    return True


def set_change_untag_port_vlan(ip, model, oid, save, vlan_id, port, debug=False):

    """
    Вешает антэг влан на порт, принимает ip хоста, модель, oid vlan-а, oid save, vlan id и port
    Возвращает текст с результатом или False в случае ошибки.
    """

    # Словарь где будут храниться временные данные
    dlink_vlans = {}

    # Получаем текущее состояние вланов на длинке вида [[имя влана, номер, состояние портов, состояние влана], ...]
    result = get_vlan(ip, model, oid)

    checker_vlan = True
    # Проверяем, чтобы указанный влан был на длинке
    for line in result:
        if vlan_id == int(line[1]):
            checker_vlan = False

    # Если влан не нашёлся - выходим из цикла
    if checker_vlan:
        if debug:
            print(result)
        return 'Нет указанного влана!'

    # Считаем четвёрку, в которой находится порт
    octet = (port - 1) // 4
    # Смотрим позицию порта в двоичной системе
    port_ii_poz = port % 4 - 1 if port % 4 else 3

    # Переменные для хранения настроек на целевом влане
    target_vlan_untag_ports = ''
    target_vlan_tag_ports = ''

    # Переменные для хранения настроек на влане, где надо убрать порт
    from_vlan_untag_ports = ''
    from_vlan_tag_ports = ''
    from_vlan_id = ''

    # Проверка, нужно ли ещё искать целевой влан
    checker_from = True

    # Идём по списку настроек вланов
    for line in result:

        # Создаём словарь вида {'номер влана': 'состояние портов'}
        dlink_vlans[line[1]] = line[2]


        # Если номер влана совпадает с вланом, который надо изменить
        if int(line[1]) == vlan_id:

            # Идём циклом по октетам портов
            for i in range(16):

                temp_ports = line[2].split()
                # Если дошли до октета, где надо заменить порт
                if i == octet:

                    # Переменные для временного хранения октета
                    temp_untag = ''
                    temp_tag = ''
                    for t in range(4):

                        # Если порт в нужной позиции
                        if t == port_ii_poz:
                            temp_tag += '1'
                            temp_untag += '1'
                        
                        # Если нет - просто переписываем
                        else:
                            temp_tag += temp_ports[i][t]
                            temp_untag += temp_ports[i][t]

                    target_vlan_untag_ports += str(hex(int(temp_untag.replace('2', '0'), 2)))[2:].upper()
                    target_vlan_tag_ports += str(hex(int(temp_tag.replace('2', '1'), 2)))[2:].upper()

                # Переписываем остальное состояние октетов
                else:
                    try:

                        # Убираем тэгированные порты для нетэгированного списка
                        target_vlan_untag_ports += str(hex(int(temp_ports[i].replace('2', '0'), 2)))[2:].upper()
                        target_vlan_tag_ports += str(hex(int(temp_ports[i].replace('2', '1'), 2)))[2:].upper()

                    # Добиваем количество символов до 16 ибо так надо длинку
                    except IndexError:
                        target_vlan_untag_ports += '0'
                        target_vlan_tag_ports += '0'

        # Ищем, из какого влана надо убрать порт
        if checker_from:

            # Временная переменная для хранения настроек портов
            temp_from_vlan_ports = []

            # Разбиваем список портов на части
            temp_ports = line[2].split()

            # Идём по октетам портов
            for k in range(len(temp_ports)):

                # Проверяем, находится ли порт, который нужно убрать из влана, здесь
                if k == octet and temp_ports[k][port_ii_poz] == '1':

                    temp_temp = ''
                    # Идём по текущему октету и меняем его параметры
                    for n in range(len(temp_ports[k])):

                        # Проверяем, соответствует ли порт нужной позиции
                        if n == port_ii_poz:

                            # Если да - убираем его оттуда
                            temp_temp += '0'

                        # В противном случае просто переписываем
                        else:
                            temp_temp += temp_ports[k][n]

                    # Добавляем изменённый октет к списку портов
                    temp_from_vlan_ports.append(temp_temp)

                    # Записываем текущий влан как целевой
                    from_vlan_id = int(line[1])
                    checker_from = False
                    continue

                # Если порт не в текущем октете - добавляем его списку
                temp_from_vlan_ports.append(temp_ports[k])

            # Проверяем, нашёлся ли нужный влан
            if not checker_from:

                # Когда собрали порты вместе - переводим их в 16-ричный вид
                for m in range(16):

                    # Заполняем переменные
                    try:
                        from_vlan_untag_ports += str(hex(int(temp_from_vlan_ports[m].replace('2', '0'), 2)))[2:].upper()
                        from_vlan_tag_ports += str(hex(int(temp_from_vlan_ports[m].replace('2', '1'), 2)))[2:].upper()

                    # Добиваем количество символов до 16 ибо так надо длинку
                    except IndexError:
                        from_vlan_untag_ports += '0'
                        from_vlan_tag_ports += '0'

    # Расширяем строки для dgs 52 моделей
    if 'DGS' in model and '52' in model:
        target_vlan_untag_ports += '00000000'
        target_vlan_tag_ports += '00000000'
        from_vlan_untag_ports += '00000000'
        from_vlan_tag_ports += '00000000'

    if debug:
        print(dlink_vlans)

    if model == 'DES-1210-28/ME B2':
        ME_model = get_firmware_snmp(ip)
    else:
        ME_model = ''

    # Если порт уже в нужном влане
    if from_vlan_id == vlan_id:
        if debug:
            print('\nВсё и так отлично!\n')
        return f"И так в этом влане"

    # Если порт не в влане
    elif not from_vlan_id:
        if debug:
            print('\nПорт не в влане!')
            print('\nTo vlan', vlan_id, '\n', target_vlan_untag_ports, '\n', target_vlan_tag_ports, '\n')

        # Правка для идиотских */ME
        if model == 'DES-1210-28/ME B3' or ME_model == 'ME new':

            # Добавляем смещение для одной цифры
            res1 = set_tag_vlan_snmp(ip, oid, vlan_id, target_vlan_tag_ports, '3')
            res2 = set_untag_vlan_snmp(ip, oid, vlan_id, target_vlan_untag_ports, '5')

        else:
            # Перекидываем в нужный
            res1 = set_tag_vlan_snmp(ip, oid, vlan_id, target_vlan_tag_ports)
            res2 = set_untag_vlan_snmp(ip, oid, vlan_id, target_vlan_untag_ports)
        
        save_conf(ip, save)
        return f"Переброшено, не был в влане"
    
    # Если есть откуда и куда
    else:
        if debug:
            print('\nFrom vlan', from_vlan_id, '\n', from_vlan_untag_ports, '\n', from_vlan_tag_ports, '\n')
            print('\nTo vlan', vlan_id, '\n', target_vlan_untag_ports, '\n', target_vlan_tag_ports, '\n')

        # Правка для идиотских DES-1210-28/ME B3
        if model == 'DES-1210-28/ME B3' or ME_model == 'ME new':

            # Добавляем смещение для одной цифры
            res1 = set_untag_vlan_snmp(ip, oid, from_vlan_id, from_vlan_untag_ports, '5')
            res2 = set_tag_vlan_snmp(ip, oid, from_vlan_id, from_vlan_tag_ports, '3')

            # Добавляем смещение для одной цифры
            res3 = set_tag_vlan_snmp(ip, oid, vlan_id, target_vlan_tag_ports, '3')
            res4 = set_untag_vlan_snmp(ip, oid, vlan_id, target_vlan_untag_ports, '5')

        else:

            # Сначала убираем из влана
            res1 = set_untag_vlan_snmp(ip, oid, from_vlan_id, from_vlan_untag_ports)
            res2 = set_tag_vlan_snmp(ip, oid, from_vlan_id, from_vlan_tag_ports)

            # Потом перекидываем в нужный
            res3 = set_tag_vlan_snmp(ip, oid, vlan_id, target_vlan_tag_ports)
            res4 = set_untag_vlan_snmp(ip, oid, vlan_id, target_vlan_untag_ports)

        save_conf(ip, save)
        
        return f"Переброшено из {from_vlan_id}"

    return False


def set_change_tag_port_vlan(ip, model, oid, save, vlan_id, port, debug=False):

    """
    Вешает на порт тэг влан, принимает ip хоста, модель, oid vlan-а, oid save, vlan id и порт.
    Возвращает текст с результатом или False в случае ошибки.
    """

    # Словарь где будут храниться временные данные
    dlink_vlans = {}

    # Получаем текущее состояние вланов на длинке вида [[имя влана, номер, состояние портов, состояние влана], ...]
    result = get_vlan(ip, model, oid)

    checker_vlan = True

    # Проверяем, есть ли указанный влан был на длинке
    for line in result:
        if vlan_id == int(line[1]):
            checker_vlan = False

    # Если влан не нашёлся - выходим из цикла
    if checker_vlan:
        if debug:
            print(result)
        return 'Нет указанного влана!'

    # Считаем четвёрку, в которой находится порт
    octet = (port - 1) // 4
    # Смотрим позицию порта в двоичной системе
    port_ii_poz = port % 4 - 1 if port % 4 else 3

    # Переменная для хранения настроек на целевом влане
    target_vlan_tag_ports = ''

    # Проверка, нужно ли ещё искать целевой влан
    checker_from = True

    # Идём по списку настроек вланов
    for line in result:

        # Создаём словарь вида {'номер влана': 'состояние портов'}
        dlink_vlans[line[1]] = line[2]

        # Если номер влана совпадает с вланом, который надо изменить
        if int(line[1]) == vlan_id:

            # Идём циклом по октетам портов
            for i in range(16):

                temp_ports = line[2].split()
                # Если дошли до октета, где надо заменить порт
                if i == octet:

                    # Переменная для временного хранения октета
                    temp_tag = ''
                    for t in range(4):

                        # Если порт в нужной позиции
                        if t == port_ii_poz:
                            temp_tag += '1'
                        
                        # Если нет - просто переписываем
                        else:
                            temp_tag += temp_ports[i][t]

                    target_vlan_tag_ports += str(hex(int(temp_tag.replace('2', '1'), 2)))[2:].upper()

                # Переписываем остальное состояние октетов
                else:
                    try:

                        # Заменяем 2 на 1 для перевода между двоичной и 16-ричной системами
                        target_vlan_tag_ports += str(hex(int(temp_ports[i].replace('2', '1'), 2)))[2:].upper()

                    # Добиваем количество символов до 16 ибо так надо длинку
                    except IndexError:
                        target_vlan_tag_ports += '0'

    # Расширяем строки для dgs 52 моделей
    if 'DGS' in model and '52' in model:
        target_vlan_tag_ports += '00000000'

    if debug:
        print(dlink_vlans)

    if debug:
        print('\nTo vlan', vlan_id, '\n', target_vlan_tag_ports, '\n')

    # Правка для идиотских DES-1210-28/ME B3
    if model == 'DES-1210-28/ME B3':

        # Потом перекидываем в нужный
        # и добавляем смещение для одной цифры
        res3 = set_tag_vlan_snmp(ip, oid, vlan_id, target_vlan_tag_ports, '3')

    else:

        # Потом перекидываем в нужный
        res3 = set_tag_vlan_snmp(ip, oid, vlan_id, target_vlan_tag_ports)

    save_conf(ip, save)

    return f"Переброшено в {vlan_id}"

    return False


def set_create_vlan(ip, model, oid, save, vlan_id, vlan_name):

    """
    Создаём влан и раскидываем на аплинки тэг, принимает ip хоста, модель, oid vlan-а, oid сэйва, vlan id и vlan name.
    """
    if 'ME' in model:
        result = set_create_vlan_telnet(ip, vlan_id, vlan_name)
    else:
        result = set_create_vlan_snmp(ip, model, oid, vlan_id, vlan_name)

        if result:
            for line in result:
                print(result)
            return result

    # Создаём кортеж для аплинков
    if '28' in model:

        ports = (25, 26, 27, 28)

    elif '52' in model:

        ports = (49, 50, 51, 52)

    # Вешаем тэг влан на аплинки
    for port in ports:

        result = set_change_tag_port_vlan(ip, model, oid, save, vlan_id, port)

    save_conf(ip, save)



if __name__ == '__main__':

    pass