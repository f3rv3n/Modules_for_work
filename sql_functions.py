#!/usr/bin/env python3

import pyodbc
import os
import config


SERVER = config.SERVER_DB
DATABASE = config.DATABASE
UID = config.USER_DB
PWD = config.PASS_DB


def connect_to_DB(server=SERVER, database=DATABASE, uid=UID, pwd=PWD):

    """
    Создаём подключение к базе.
    Возвращает cursor
    """

    drivers = [item for item in pyodbc.drivers()]
    driver = drivers[-1]
    con_string = f"DRIVER={driver};DATABASE={database};SERVER={server};UID={uid};PWD={pwd}"
    cnxn = pyodbc.connect(con_string, autocommit=True)

    return cnxn.cursor()


def create_tables(cursor):

    """
    Создаёт таблицы из файла, принимает курсор.
    Возвращает Success в случае отсутствия ошибок
    """

    print('Creating tables...')
    with open('sql/create_tables') as f:
        schema = f.read()
    cursor.execute(schema)
    return 'Success'


def create_FK(cursor):

    """
    Создаёт внешние ключи из файла, принимает cursor.
    Возвращает Success в случае отсутствия ошибок
    """

    print('Creating FK...')
    with open('sql/create_FK') as f:
        schema = f.read()
    cursor.execute(schema)
    return 'Success'


def create_triggers(cursor):

    """
    Читает из папки sql файлы с trigger в имени и создаёт из них триггеры, принимает курсор.
    Возвращает Success в случае отсутствия ошибок
    """

    print('Creating triggers...')

    trigger_path = Path('.') / 'sql'
    files = os.listdir(trigger_path)
    for line in files:
        if 'trigger' in line:

            with open(f"sql/{line}") as f:
                schema = f.read()
            cursor.execute(schema)

    return 'Success'


def get_oid(cursor, command):

    """
    Отправляет запрос в таблицу с OID для заданной команды, принимает cursor и команду
    Возвращает словарь вида {устройство - оид}
    """

    res = cursor.execute(f"SELECT Device_info.Vers_Hard, Snmp.Oid "
                         f"FROM Snmp, Device_info "
                         f"WHERE Snmp.ID_VH = Device_info.ID AND Snmp.Command = '{command}'")

    result = {}
    for line in res:
        result[line[0]] = line[1]

    return result


def dlink_to_sql(ip, mac, m_f, line):

    """
    Обновление\добавление записей в базу, принимает ip хоста, mac, модель и версию прошивки и действие.
    Возвращает True или False в зависимости от результата
    """

    cursor = connect_to_DB()
    try:

        # В зависимости от переданного параметра обращаемся к базе
        if line == 'INSERT':
        
            # Разбиваем ip адрес на октеты для получения подсети
            net = ip.split('.')
            subnet = f"{net[0]}.{net[1]}.{net[2]}"
        
            cursor.execute(f"INSERT INTO Dlink (IP, Mac, Subnet, ID_VH, Date_check, Active) "
                           f"VALUES ('{ip}', '{mac}', '{subnet}', "
                           f"(SELECT ID FROM Device_info WHERE Vers_Hard = '{m_f}'), (SELECT GETDATE()), '0')")

        elif line == 'UPDATE':
            cursor.execute(f"UPDATE Dlink SET Mac = '{mac}', "
                           f"ID_VH = (SELECT ID FROM Device_info WHERE Vers_Hard = '{m_f}'), Date_check = (SELECT GETDATE()) "
                           f"WHERE IP = '{ip}'")

    except:
        cursor.close()
        return False

    cursor.close()
    return True


def get_dlink(cursor, check=True):

    """
    Отправляет запрос в таблицу dlink, принимает cursor.
    Возвращает список вида [ [модель, ip адрес, mac адрес], ...]
    """

    res = cursor.execute(f"SELECT Device_info.Vers_Hard, Dlink.IP, Dlink.Mac, Dlink.Active "
                         f"FROM Dlink, Device_info "
                         f"WHERE Dlink.ID_VH = Device_info.ID")

    result = []
    for line in res:

        # Если больше 100 пропусков пингов - не добавляем
        if int(line[3]) < 100:
            result.append([line[0], line[1], line[2]])

        # Если только не отключен фильтр
        elif not check:
            result.append([line[0], line[1], line[2]])

    return result


def router_to_sql(ip, model, version, line):

    """
    Обновление\добавление записей в базу, принимает ip хоста, модель, версию и действие.
    Возвращает Success или Fail в зависимости от результата

    """

    cursor = connect_to_DB()

    try:
        # В зависимости от переданного параметра обращаемся к базе
        if line == 'INSERT':
            
            # Разбиваем ip адрес на октеты для получения подсети
            net = ip.split('.')
            subnet = f"{net[0]}.{net[1]}.{net[2]}"

            cursor.execute(f"INSERT INTO Routers (IP, Model, Version, Subnet, Date_check, Active) "
                           f"VALUES ('{ip}', '{model}', '{version}', '{subnet}', (SELECT GETDATE()), '0')")

        elif line == 'UPDATE':
            cursor.execute(f"UPDATE Routers SET Model = '{model}', Version = '{version}', Date_check = (SELECT GETDATE()) "
                           f"WHERE IP = '{ip}'")
        print(f"{line} {ip} successful")

    except:
        print(f"Somethink wrong with {line} on host {ip}")
        cursor.close()
        return 'Fail'

    cursor.close()
    return 'Success'


def get_routers(cursor, check=True):

    """
    Отправляет запрос в таблицу routers, принимает cursor.
    Возвращает список вида [ [ip адрес, модель, версия], ...]
    """

    res = cursor.execute(f"SELECT IP, Model, Version, Active FROM Routers")
    
    result = []
    for line in res:

        # Если больше 100 пропусков пингов - не добавляем
        if int(line[3]) < 100:
            result.append([line[0], line[1], line[2]])

        # Если только не отключен фильтр
        elif not check:
            result.append([line[0], line[1], line[2]])

    return result


def wifi_to_sql(ip, mac, model, line):

    """
    Обновление\добавление записей в базу, принимает ip хоста, мак, модель и действие.
    Возвращает Success или Fail в зависимости от результата.
    """

    cursor = connect_to_DB()

    try:
        # В зависимости от переданного параметра обращаемся к базе
        if line == 'INSERT':
            
            # Разбиваем ip адрес на октеты для получения подсети
            net = ip.split('.')
            subnet = f"{net[0]}.{net[1]}.{net[2]}"

            cursor.execute(f"INSERT INTO Wifi (IP, Model, Mac, Subnet, Date_check) "
                           f"VALUES ('{ip}', '{model}', '{mac}', '{subnet}', (SELECT GETDATE()))")

        elif line == 'UPDATE':
            cursor.execute(f"UPDATE Wifi SET Model = '{model}', Mac = '{mac}', Date_check = (SELECT GETDATE()) "
                           f"WHERE IP = '{ip}'")
        print(f"{line} {ip} successful")

    except:
        print(f"Somethink wrong with {line} on host {ip}")
        cursor.close()
        return 'Fail'

    cursor.close()
    return 'Success'


def get_wifi(cursor):

    """
    Отправляет запрос в таблицу wifi, принимает cursor.
    Возвращает список вида [ [ip адрес, мак адрес, модель], ...]
    """

    res = cursor.execute(f"SELECT IP, Mac, Model FROM Wifi")
    
    result = []
    for line in res:
        result.append([line[0], line[1], line[2]])

    return result


def port_sec_to_sql(ip, port, status, max_hosts, line):

    """
    Обновление\добавление записей в базу, принимает ip хоста, порт, статус, максимум хостов и действие.
    Возвращает Success или Fail в зависимости от результата
    """

    cursor = connect_to_DB()

    try:
        # В зависимости от переданного параметра обращаемся к базе
        if line == 'INSERT':

            cursor.execute(f"INSERT INTO Port_security (ID_device, Port, Status, Max_hosts) "
                           f"VALUES ((SELECT ID FROM Dlink WHERE IP = '{ip}'), '{port}', '{status}', '{max_hosts}')")

        elif line == 'UPDATE':
            cursor.execute(f"UPDATE Port_security SET Status = '{status}', Max_hosts = '{max_hosts}' "
                           f"WHERE ID_device = (SELECT ID FROM Dlink WHERE IP = '{ip}') AND Port = '{port}'")
        print(f"{line} on host {ip} port {port} successful")

    except:
        print(f"Somethink wrong with {line} on host {ip}, port {port}")
        cursor.close()
        return 'Fail'

    cursor.close()
    return 'Success'


def get_port_sec_from_sql(cursor, ip):

    """
    Запрос состояния port security на хосте, принимает cursor и ip хоста.
    Возвращает список вида [ [ID устройства, порт, статус, максимум хостов], ...]
    """

    res = cursor.execute(f"SELECT ID_device, Port, Status, Max_hosts FROM Port_security "
                         f"WHERE ID_device = (SELECT ID FROM Dlink WHERE IP = '{ip}')")
    
    result = []
    for line in res:
        result.append([line[0], line[1], line[2], line[3]])

    return result


def users_to_sql(cursor, ip, mac, port, vlan):

    """
    Добавление записей в базу, принимает cursor, ip хоста, мак, порт и влан.
    Возвращает Success или Fail в зависимости от результата.
    """

    try:

        cursor.execute(f"INSERT INTO Users_history (ID_device, Mac, Port, Vlan, Date_check) "
                       f"VALUES ((SELECT ID FROM Dlink WHERE IP = '{ip}'), '{mac}', '{port}', '{vlan}', (SELECT GETDATE()))")

    except:
        print(f"Somethink wrong with mac {mac}")
        return 'Fail'

    return 'Success'


def get_users(cursor, mac, top=5):

    """
    Выборка последних 5 записей о маке, принимает cursor, mac и кол-во записей.
    Возвращает список вида [ [ip адрес, порт, влан], ...]
    """

    res = cursor.execute(f"SELECT TOP ({int(top)}) (SELECT IP FROM Dlink WHERE Dlink.ID = Users_history.ID_device), Port, Vlan, Date_check "
                         f"FROM Users_history "
                         f"WHERE Mac = '{mac}' ORDER BY Date_check DESC")

    result = []
    for line in res:
        result.append([line[0], line[1], line[2], line[3]])

    return result if len(result) > 0 else False


def macs_routers_to_sql(ip, mac):

    """
    Обновление\добавление записей в базу, принимает ip хоста и мак.
    Возвращает True или False в зависимости от успеха.
    """

    cursor = connect_to_DB()

    try:

        cursor.execute(f"INSERT INTO Macs (IP, Mac) "
                       f"VALUES ('{ip}', '{mac}')")

    except:
        print(f"Somethink wrong on mac {mac}")
        cursor.close()
        return False

    cursor.close()
    return True


def get_macs_routers(cursor):

    """
    Отправляет запрос в таблицу с мак адресами роутеров, принимает cursor.
    Возвращает список вида [ [ip адрес, мак адрес], ...]
    """

    res = cursor.execute(f"SELECT IP, Mac FROM Macs")

    result = []
    for line in res:
        result.append([line[0], line[1]])

    return result


def get_office_dlink(cursor):

    """
    Отправляет запрос в таблицу офисных dlink-ов, принимает cursor.
    Возвращает список вида [ [модель, ip адрес, mac адрес], ...]
    """

    res = cursor.execute(f"SELECT Device_info.Vers_Hard, Dlink_office.IP, Dlink_office.Mac "
                         f"FROM Dlink_office, Device_info "
                         f"WHERE Dlink_office.ID_VH = Device_info.ID")

    result = []
    for line in res:
        result.append([line[0], line[1], line[2]])

    return result


def get_devices_subnet(ip):

    """
    Выборка всех устройств из указанной подсети, принимает ip подсети.
    Возвращает список вида [[ip роутера, модель роутера], [мак адреса роутера], [ip свитча\wifi, мак свитча\wifi, модель свитча\wifi]...]
    """

    cursor = connect_to_DB()
    command = [f"SELECT IP, Model FROM Routers WHERE Subnet = '{ip}'",
               f"SELECT Mac FROM Macs WHERE IP = (SELECT IP FROM Routers WHERE Subnet = '{ip}')",
               f"SELECT IP, Mac, (SELECT Vers_Hard FROM Device_info WHERE ID = ID_VH) FROM Dlink WHERE Subnet = '{ip}'",
               f"SELECT IP, Mac, Model FROM Wifi WHERE Subnet = '{ip}'"]
    res = []
    result = []
    temps = []
    temp = cursor.execute(command[0])
    for line in temp:
        result.append([line[0], line[1]])
    temp = cursor.execute(command[1])
    for line in temp:
        temps.append([line])
    result.append(temps)
    for line in command[2:]:
        res = cursor.execute(line)
        for lin in res:
            result.append([lin[0], lin[1], lin[2]])
    cursor.close()
    return result


def dlink_office_to_sql(ip, mac, model, line):

    """
    Обновление\добавление записей в базу, принимает ip хоста, мак, модель и действие.
    Возвращает True или False в зависимости от успеха.
    """

    cursor = connect_to_DB()
    try:

        print(f"Trying to {line} host {ip} {model}")
        # В зависимости от переданного параметра обращаемся к базе
        if line == 'INSERT':
        
            cursor.execute(f"INSERT INTO Dlink_office (IP, Mac, ID_VH, Date_check) "
                           f"VALUES ('{ip}', '{mac}',  "
                           f"(SELECT ID FROM Device_info WHERE Vers_Hard = '{model}'), (SELECT GETDATE()))")

        elif line == 'UPDATE':
            cursor.execute(f"UPDATE Dlink_office SET Mac = '{mac}', "
                           f"ID_VH = (SELECT ID FROM Device_info WHERE Vers_Hard = '{model}'), Date_check = (SELECT GETDATE()) "
                           f"WHERE IP = '{ip}'")
        print(f"{line} {ip} successful")
    except:
        print(f"Somethink wrong with {line} on host {ip}")
        cursor.close()
        return False

    cursor.close()
    return True


def file_name_into_logs(cursor, name):

    """
    Добавляем имя скрипта в таблицу для записи логов, принимает cursor и имя файла.
    Возвращает True если не ошибки, иначе False
    """

    try:
        cursor.execute(f"INSERT INTO Functions_name (Func_name) VALUES ('{name}')")
        return True
    except:
        return False


def write_log(name, id_mess, mess, cursor=False, check=True):

    """
    Записывает лог в базу, принимает имя скрипта, уровень сообщения, сообщение, может принять cursor.
    Возвращает True если не ошибки, иначе False
    """

    if not cursor:
        cursor = connect_to_DB(database='Logs')

    try:
        cursor.execute(f"INSERT INTO Logs_scripts (Date_get, ID_func, Mess, ID_mess) "
                       f"VALUES ((SELECT GETDATE()), (SELECT ID FROM Functions_name WHERE Func_name = '{name}'), "
                       f"N'{mess}', '{id_mess}')")
        return True

    # Ловит ошибку, если имени скрипта ещё нет в базе 
    except pyodbc.IntegrityError as e:
        if "Cannot insert the value NULL into column 'ID_func'" in str(e):
            if check:

                # Вызывает функцию добавления имени скрипта в базу
                file_name_into_logs(cursor, name)
                res = write_log(name, id_mess, mess, cursor, False)
                return res

        return False
    except:
        return False


def get_logs(date_get='', script='', mess='', level='', top=10, cursor=''):

    """
    Достаёт лог из базы, может принимать дату в формате year-month-day, имя скрипта,
    сообщение или его часть, уровень сообщения, количество записей (по умолчанию 10), cursor.
    Возвращает список с ошибками если ок, иначе False
    """

    if not cursor:
        cursor = connect_to_DB(database='Logs')

    inject = ''

    if date_get:
        inject = f"(SELECT CAST(Date_get AS date)) = '{date_get}'"
    elif script:
        inject = f"ID_func = (SELECT ID FROM Functions_name WHERE Functions_name.Func_name LIKE '%{script}%')"
    elif mess:
        inject = f"Mess LIKE '%{mess}%'"
    elif level:
        inject = f"ID_mess = '{level}'"


    if inject:
        res = cursor.execute("SELECT Date_get, (SELECT Func_name FROM Functions_name WHERE Functions_name.ID = ID_func), "
                             "Mess ,(SELECT Mess_level FROM Level_mess WHERE Level_mess.ID = ID_mess) as Level "
                            f"FROM Logs_scripts WHERE {inject} ORDER BY Date_get DESC")

    else:
        res = cursor.execute(f"SELECT TOP ({top}) Date_get"
                             ",(SELECT Func_name FROM Functions_name WHERE Functions_name.ID = ID_func)"
                             ",[Mess]"
                             ",(SELECT Mess_level FROM Level_mess WHERE Level_mess.ID = ID_mess)"
                             "FROM Logs_scripts ORDER BY Date_get DESC"
                            )

    result = []
    i = 0
    for line in res:
        if i == top:
            break
        i += 1
        result.append(line)

    return result


def inter_to_sql(cursor, ip, inter, line='UPDATE'):

    """
    Обновление\добавление активных интерфейсов в базу, принимает cursor и строку с интерфейсами.
    Возвращает True или Fail в зависимости от результата.
    """

    try:

        if line == 'INSERT':
            cursor.execute(f"INSERT INTO Inet (ID_router, Interfaces) "
                           f"VALUES ((SELECT ID FROM Routers WHERE IP = '{ip}'), '{inter}')")

        elif line == 'UPDATE':
            cursor.execute(f"UPDATE Inet SET Interfaces = '{inter}' "
                           f"WHERE ID_router = (SELECT ID FROM Routers WHERE IP = '{ip}')")

    except:
        print(f"Somethink wrong with ip {ip}")
        return False

    return True


def get_inet_inter(cursor, ip):

    """
    Получение записи об активных интерфейсах из базы, принимает cursor и ip хоста.
    Возвращает результат выборки или False, если нет IP роутера в базе
    """

    res = cursor.execute(f"SELECT Interfaces FROM Inet WHERE ID_router = (SELECT ID FROM Routers WHERE IP = '{ip}')")
    try:
        result = next(res)
        return result[0]
    except StopIteration:
        return False


def get_active(cursor, device):

    """
    Получение записи о действующих устройствах, принимает cursor и тип хостов.
    Возвращает результат выборки или False
    """

    res = cursor.execute(f"SELECT IP, Active FROM {device}")

    result = []
    for line in res:
        result.append([line[0], line[1]])

    return result


def active_to_sql(device, ip, active):

    """
    Обновление\добавление активных устройств в базу, принимает ip хоста и текущую активность.
    Возвращает True или Fail в зависимости от результата.
    """

    try:

        cursor = connect_to_DB()
        cursor.execute(f"UPDATE {device} SET Active = {active} WHERE IP = '{ip}'")

    except:
        print(f"Somethink wrong with ip {ip}")
        cursor.close()
        return False

    cursor.close()
    return True



# Основное меню для тестов
if __name__ == '__main__':

    pass
