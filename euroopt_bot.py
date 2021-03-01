#!/usr/bin/env python3

import telebot
import os
import subprocess
import config
from random import randint
from get_from_excel import get_info_from_excel
from sql_functions import *
from modules_for_routers import *
from modules_for_dlink import *
from datetime import datetime


# Токен для телеграм бота
TOKEN = config.TOKEN

# Список доверенных юзеров
Good_id = config.GOOD_ID

# Список юзеров с офиса
Office_id = config.OFFICE_ID

# Список юзеров, кому разрешено делать рассылку
CAP = config.CAP

# Подключение бота и запрет на использование многопоточности
bot = telebot.TeleBot(TOKEN, threaded=False)

# Вывод клавиатуры
keyboard1 = telebot.types.ReplyKeyboardMarkup(True, True)
keyboard1.row('Покажи', 'Пинг', 'Ребут')
keyboard1.row('Номер', 'Дхцп', 'Арп')
keyboard1.row('Мак', 'Инет', 'Секур')
keyboard1.row('Влан', 'Порты')

# Списки для обработки команд
Answers = ['Ой фсё!', 'Пиши нормально!', 'Да ну тебя!', 'Я с тобой не разговариваю!', 'Отстань, противный!', 'Изыди!']
Bots = ['бот', 'bot', ]
Tests = ['тест', 'test', ]
Shows = ['покажи', 'покаж', 'show', ]
Pings = ['пинг', 'пингани', 'ping', ]
Reboots = ['reboot', 'ребут', ]
Numbers = ['номер', 'number', ]
Dhcps = ['dhcp', 'дхцп', ]
Arps = ['arp', 'арп', ]
Macs = ['mac', 'мак', ]
Inets = ['inet', 'инет', ]
Securs = ['secur', 'секур', ]
Vlans = ['влан', 'vlan', ]
Ports = ['порты', 'ports', ]

# Функция для вывода помощи
@bot.message_handler(commands=['start'])
def start_message(message):

    # Переводим юниксовое время в обычное со поправкой на часовой пояс
    date_sms = int(message.date) + 10800
    date_sms = datetime.utcfromtimestamp(date_sms).strftime('%Y-%m-%d %H:%M:%S')

    # Если сообщение пришло от проверенного пользователя
    if message.from_user.id in Good_id.keys():

        with open ('bot_known.log', 'a') as f:
            print(f"{date_sms} писал {Good_id[message.from_user.id]} сообщение {message.text}", file=f)
        bot.send_message(message.chat.id, 'Нажмите на кнопку для вывода справки о соответствующей команде', reply_markup=keyboard1)

    # Если пользователя нет в числе проверенных выводим сообщение и добавляем его в лог-файл
    else:
        bot.send_message(message.chat.id, f'{message.from_user.id}, я тебя не знаю!')

        with open ('bot_unknown.log', 'a') as f:

            print(f"{date_sms} писал {message.from_user.id} сообщение {message.text}", file=f)


# Функция для обработки прилетающих команд
@bot.message_handler(content_types=['text'])
def reading_commands(message):

    # Переводим полученное сообщение в нижний регистр
    mess = message.text.lower().split()

    # Переводим юниксовое время в обычное со поправкой на часовой пояс
    date_sms = int(message.date) + 10800
    date_sms = datetime.utcfromtimestamp(date_sms).strftime('%Y-%m-%d %H:%M:%S')

    # Если сообщение пришло от проверенного пользователя
    if message.from_user.id in Good_id.keys():

        with open ('bot_known.log', 'a') as f:
            print(f"{date_sms} писал {Good_id[message.from_user.id]} сообщение {message.text}", file=f)
        
        # Проверяем, с каких букв начинается сообщение и действуем в соответствии с этим
        if mess[0]in Bots:
            bot.send_message(message.chat.id, f'Да, {message.from_user.username}?')

        # Вывод различной информации по сообщению пользователя, 
        elif mess[0] in Tests:
            print(message.date)
            date_sms = int(message.date) + 10800
            date_sms = datetime.utcfromtimestamp(date_sms).strftime('%Y-%m-%d %H:%M:%S')
            bot.send_message(message.chat.id, f"{message}\n{date_sms}")

        # Справочная инфа о Покажи
        elif mess[0] in Shows and len(mess) == 1:
            bot.send_message(message.chat.id, 'Для вывода карты сетевых устройств на магазине писать команду вида:\n'
                                              'Покажи 23.230\n'
                                              'или\n'
                                              'Покаж 23.230\n'
                                              'или\n'
                                              'Show 23.230\n\n'
                                              "Если карта пустая или на ней не все устройства - проверьте настройки dlink-ов на магазине"
                                              "или правильность подключения их в роутер")

        # Если начинается на покажи - проверяем, чтобы было 2 октета во второй части сообщения
        # И пробуем вывести файл с указанным адресом либо сообщение о его отсутствии
        elif mess[0]in Shows and len(mess[1].split('.')) == 2:

            # Определяем вторую часть сообщение как имя файла
            file = mess[1]
            try:

                # Пробуем открыть файл с указанным именем
                net = open("/var/www/webApp/webApp/static/images/172." + file + ".png", 'rb')
                # Отправляем ботом картинку
                bot.send_photo(message.chat.id, net)
                # Запускаем функцию по получению сетевых устройств в заданной подсети
                devices = get_devices_subnet(f"172.{mess[1]}")
                # Создаём временные переменные для хранения ответа
                macs = ''
                switchs = ''
                # Получаем из ответа маки роутера
                for line in devices[1]:
                    macs += line[0][0] + ', '
                # Получаем из ответа сетевые устройства
                for line in sorted(devices[2:]):
                    switchs += f"\nIP = {line[0]}, Mac = {line[1].upper()}, Model = {line[2]};"
                # Отправляем ответ со всем вышеперечисленным
                bot.send_message(message.chat.id, f"Роутер {devices[0][1]} с адресом {devices[0][0]}\n"
                                                  f"Мак адреса:\n{macs[:-2]}"
                                                  f"\n\nОстальные устройства: {switchs}")

            # Если файл открыть не удалось - отправляем сообщение с инфо
            except:
                bot.send_message(message.chat.id, 'Такой карты у меня нет!')

        # Справочная инфа о Пинг
        elif mess[0] in Pings and len(mess) == 1:
            bot.send_message(message.chat.id, 'Для пинга писать команду вида:\n'
                                              'Пинг 172.23.230.100\n'
                                              'или\n'
                                              'Ping 172.23.230.100\n')

        # Если начинается на пинг - проверяем, чтобы было 4 октета во второй части сообщения
        elif mess[0] in Pings and len(mess[1].split('.')) == 4:

            # Обращаемся к функции с пингом и выводим ответ в зависимости от результата
            bot.send_message(message.chat.id, f"Хост {'доступен' if ping_host(mess[1]) else 'недоступен'}")

        # Справочная инфа о Номер
        elif mess[0] in Numbers and len(mess) == 1:
            bot.send_message(message.chat.id, 'Для получения информации о подсети магазина и его адресе писать команду вида:\n'
                                              'Номер 760\n'
                                              'или\n'
                                              'Number 760\n')

        # Если начинается на номер - вызываем функцию проверки номера и выводим ответ
        elif mess[0] in Numbers:

            # Берём вторую часть сообщения и отправляем её в функцию
            nomer = get_info_from_excel(mess[1])
            # Если ответ нашёлся - выводим сообщение с инфо о магазине
            if nomer:
                bot.send_message(message.chat.id, f"У магазина {mess[1]} подсеть {nomer['ip']} и адрес {nomer['address']}")
            # Если нет - выводим сообщение об ошибки
            else:
                bot.send_message(message.chat.id, f"Не знаю про магазин {mess[1]}")

        # Справочная инфа о Дхцп
        elif mess[0] in Dhcps and len(mess) == 1:
            bot.send_message(message.chat.id, 'Для вывода информации о dhcp клиентах на магазине писать команду вида:\n'
                                              'Дхцп 172.23.230.1\n'
                                              'или\n'
                                              'Dhcp 172.23.230.1\n')

        # Если начинается на dhcp - проверяем, чтобы было 4 октета во второй части сообщения
        # Пробуем пингануть адрес и если успешно - получаем модель роутера и обращаемся к функции
        elif mess[0] in Dhcps and len(mess[1].split('.')) == 4:

            # Проверяем, доступен ли хост
            if ping_host(mess[1]):

                # Подключаемся к базе и делаем запрос модели по ip
                cursor = connect_to_DB()
                result = cursor.execute(f"SELECT Model FROM Routers WHERE IP = '{mess[1]}'")
                # Смотрим что в результате и в зависимости от этого обращаемся к одной из функций
                try:
                    if 'ZyWALL' in next(result)[0]:
                        temp = get_dhcp_zywall(mess[1]) 
                    else:
                        temp = get_dhcp_mikrotik(mess[1])
                    # Временная переменная для хранения результата
                    result = ''
                    # Идём по строкам ответа и собираем их в одну переменную для вывода одним сообщением
                    for line in temp:
                        result += f"\nIP = {line[0]}, Mac = {line[1]}, Name = {line[2]};"
                    # Выводим полученную информацию
                    bot.send_message(message.chat.id, f"Клиенты на роутере {mess[1]}:\n{result}" if temp else "Не удалось подключиться к хосту")
                    # Закрываем соединение с базой
                    cursor.close()
                # Если в базе не нашлась модель роутера - выводим следующее сообщение и закрываем соединение с базой
                except StopIteration:
                    bot.send_message(message.chat.id, "Не знаю такой роутер")
                    cursor.close()
            # Если хост недоступен - выводим следующее сообщение
            else:
                bot.send_message(message.chat.id, "Хост недоступен")

        # Справочная инфа о Ребут
        elif mess[0] in Reboots and len(mess) == 1:
            bot.send_message(message.chat.id, 'Для перезагрузки роутера писать команду вида:\n'
                                              'Ребут 172.23.230.1\n'
                                              'или\n'
                                              'Reboot 172.23.230.1\n')

        # Если начинается на ребут - вызываем функцию для перезагрузки роутера
        elif mess[0] in Reboots and len(mess[1].split('.')) == 4:

            # Проверяем, доступен ли хост
            if ping_host(mess[1]):

                # Подключаемся к базе и делаем запрос модели по ip
                cursor = connect_to_DB()
                result = cursor.execute(f"SELECT Model FROM Routers WHERE IP = '{mess[1]}'")
                # Смотрим что в результате и в зависимости от этого обращаемся к одной из функций
                try:
                    if 'ZyWALL' in next(result)[0]:
                        result = reboot_zywall(mess[1]) 
                    else:
                        result = reboot_mikrotik(mess[1])
                    # Отправляем ответ в зависимости от ответа функции
                    bot.send_message(message.chat.id, f"Хост отправлен в ребут" if result else "Не удалось подключиться к хосту")
                    # Закрываем соединение с базой
                    cursor.close()
                # Если в базе не нашлась модель роутера - выводим следующее сообщение и закрываем соединение с базой
                except StopIteration:
                    bot.send_message(message.chat.id, "Не знаю такой роутер")
                    cursor.close()
            # Если хост недоступен - выводим следующее сообщение
            else:
                bot.send_message(message.chat.id, "Хост недоступен")

        # Справочная инфа об Арп
        elif mess[0] in Arps and len(mess) == 1:
            bot.send_message(message.chat.id, 'Для вывода арп с роутера писать команду вида:\n'
                                              'Арп 172.23.230.1\n'
                                              'или\n'
                                              'Arp 172.23.230.1\n')

        # Если начинается на арп - проверяем, чтобы было 4 октета во второй части сообщения
        # Пробуем пингануть адрес и если успешно - получаем модель роутера и обращаемся к функции
        elif mess[0] in Arps and len(mess[1].split('.')) == 4:

            # Проверяем, доступен ли хост
            if ping_host(mess[1]):

                # Подключаемся к базе и делаем запрос модели по ip
                cursor = connect_to_DB()
                result = cursor.execute(f"SELECT Model FROM Routers WHERE IP = '{mess[1]}'")
                # Смотрим что в результате и в зависимости от этого обращаемся к одной из функций
                try:
                    if 'ZyWALL' in next(result)[0]:
                        temp = get_arp_zywall(mess[1]) 
                    else:
                        temp = get_arp_mikrotik(mess[1])
                    # Временная переменная для хранения результата
                    result = ''
                    # Идём по строкам ответа и собираем их в одну переменную для вывода одним сообщением
                    for line in temp:
                        result += f"\nIP = {line[0]}, Mac = {line[1]};"
                    # Выводим полученную информацию
                    bot.send_message(message.chat.id, f"Арпы на роутере {mess[1]}:\n{result}" if temp else "Не удалось подключиться к хосту")
                    # Закрываем соединение с базой
                    cursor.close()
                # Если в базе не нашлась модель роутера - выводим следующее сообщение и закрываем соединение с базой
                except StopIteration:
                    bot.send_message(message.chat.id, "Не знаю такой роутер")
                    cursor.close()
            # Если хост недоступен - выводим следующее сообщение
            else:
                bot.send_message(message.chat.id, "Хост недоступен")

        # Справочная инфа о Мак
        elif mess[0] in Macs and len(mess) == 1:
            bot.send_message(message.chat.id, 'Для поиска мак адреса писать команду вида:\n'
                                              'Мак 11:22:33:44:55:66\n'
                                              'или\n'
                                              'Mac 11:22:33:44:55:66\n\n'
                                              "':' можно заменить на '-' или писать вообще без разделителя\n\n"
                                              'Выводятся последние пять записей. На магазинах есть дубли мак-адресов. '
                                              'Если заметите как мак скачет между разными магазами - советую что-то с этим сделать\n')

        # Если начинается на мак - проверяем, чтобы во второй части сообщения было 6 октетов
        elif mess[0] in Macs and (len(mess[1].split('-')) == 6 or len(mess[1].split(':')) == 6 or len(mess[1]) == 12):

            # Создаём переменную для хранения мака
            mac = ''
            
            # Если мак без разделителей - генерируем их
            if len(mess[1]) == 12:
                for i in range(int(len(mess[1]) / 2)):
                    mac += mess[1][i*2] + mess[1][i*2 + 1] + ':'
                mac = mac[:-1]

            # В противном случае - заменяем '-' на ':'
            else:
                mac = mess[1].replace("-", ":")

            # Переводим в верхний регистр для поиска в базе
            mac = mac.upper()

            # Подключаемся к базе и запрашиваем историю по мак-адресам
            # По умолчанию возвращается не более пяти записей вида [ [ip адрес, порт, влан], ...]
            cursor = connect_to_DB()
            result = get_users(cursor, mac)
            cursor.close()

            # Если мак нашёлся в базе - генерируем результат в одну строку для вывода в сообщении
            if result:
                line = ''
                for res in result:
                    line += f"\nIP = {res[0]}, Port = {res[1]}{' , Vlan = ' + res[2] if int(res[2]) != 1 else ''}, Date = {str(res[3])[:19]}"

                bot.send_message(message.chat.id, f"Мак {mac} найден.{line}")

            # Если нет - выводим сообщение о его отсутствии
            else:
                bot.send_message(message.chat.id, f"Мак {mac} не найден.")

        # Справочная инфа об Инет
        elif mess[0] in Inets and len(mess) == 1:
            bot.send_message(message.chat.id, 'Для проверки доступности интернета на роутере писать сообщение вида:\n'
                                              'Инет 172.23.230.1\n'
                                              'или\n'
                                              'Inet 172.23.230.1\n'
                                              'Команда может выполняться несколько десятков секунд, особенно на зиволе\n')

        # Если начинается на инет - проверяем, чтобы во второй части сообщения было 4 октета
        elif mess[0] in Inets and len(mess[1].split('.')) == 4:

            # Проверяем, доступен ли хост
            if ping_host(mess[1]):

                # Подключаемся к базе и делаем запрос модели по ip
                cursor = connect_to_DB()
                result = cursor.execute(f"SELECT Model FROM Routers WHERE IP = '{mess[1]}'")
                # Смотрим что в результате и в зависимости от этого обращаемся к одной из функций
                try:
                    if 'ZyWALL' in next(result)[0]:
                        result = check_inet_zywall(mess[1])
                    else:
                        result = check_inet_mikrotik(mess[1])
                    # Если ответ вернулся - создаём временную переменную
                    if result:
                        res = ''
                        # Идём по строкам ответа и собираем их в одну переменную для вывода одним сообщением
                        for line in result:
                            res += f"\nС интерфейса {line[1]} {line[4] if line[2] == 'No' else line[3]} интернет {'' if line[-1] == 'Жив' else 'не '}доступен"

                        # Выводим полученную информацию
                        bot.send_message(message.chat.id, f"На магазе {mess[1]} дела с интернетом обстоят так:" + res)
                        # Закрываем соединение с базой
                        cursor.close()

                    # Если в ответе функции False - выводим инфо об этом
                    else:
                        bot.send_message(message.chat.id, f"На магазе {mess[1]} что-то пошло не так")
                        cursor.close()

                # Если в базе не нашлась модель роутера - выводим следующее сообщение и закрываем соединение с базой
                except StopIteration:
                    bot.send_message(message.chat.id, "Не знаю такой роутер")
                    cursor.close()

            # Если хост недоступен - выводим следующее сообщение
            else:
                bot.send_message(message.chat.id, "Хост недоступен")

        # Справочная инфа о Секур
        elif mess[0] in Securs and len(mess) == 1:
            bot.send_message(message.chat.id, 'Для проверки настроек port-security на длинке писать сообщение вида:\n'
                                              'Секур 172.23.230.2\n'
                                              'или\n'
                                              'Secur 172.23.230.2\n\n'
                                              'Либо, если интересуют настройки конкретного порта:\n'
                                              'Секур 172.23.230.2 22\n'
                                              'или\n'
                                              'Secur 172.23.230.2 22\n\n'
                                              'Для некоторых редких моделей команда пока не работает.\n')

        # Если начинается на секур - проверяем, чтобы было 4 октета во второй части сообщения
        # и пробуем пингануть адрес
        elif mess[0] in Securs and len(mess[1].split('.')) == 4:

            # Проверяем, доступен ли хост
            if ping_host(mess[1]):

                # Подключение к базе и запрос текущего оборудования
                # Возвращается ответ в вида вложенного списка [[модель, ip адрес, mac адрес], ...]
                cursor = connect_to_DB()
                dlinks = get_dlink(cursor)
                port_security = get_oid(cursor, 'port_security')
                cursor.close()
                # Ищем модель длинка в базе
                for dlink in dlinks:
                    if mess[1] == dlink[1]:
                        model = dlink[0]
                        break

                # Смотрим на длину сообщения и действуем исходя из этого
                # Если в сообщении три части - проверяем, является ли третья числом
                if len(mess) == 3:
                    if mess[2].isdigit():
                        # На случай встречи модели, для которой нет oid
                        try:
                            # Вызываем функцию для получения настроек порта
                            status, hosts = get_port_sec_one_snmp(mess[1], port_security[model], int(mess[2]))
                            # Выводим полученную информацию
                            bot.send_message(message.chat.id, 
                                             f"У хоста {mess[1]} порту {mess[2]} состояние "
                                             f"{'включен' if status == '1' else 'выключен'} и максимум {hosts} хостов")
                        # Если для указанной модели нет snmp - выводим это сообщение
                        except KeyError:
                            bot.send_message(message.chat.id, f"Устройство {mess[1]} пока недоступно для опроса")
                        # Если для указанного адреса не нашлась модель - выводим это сообщение
                        except NameError:
                            bot.send_message(message.chat.id, f"С адресом {mess[1]} не работаю!")
                    else:
                        bot.send_message(message.chat.id, f"Цифры вводи, цифры!")

                # Если введено два слова, выводим полный список настроек
                elif len(mess) == 2:
                    # На случай встречи модели, для которой нет oid
                    try:
                        result = get_port_sec_all_snmp(mess[1], port_security[model])
                        res = ''
                        for line in range(len(result[0])):
                            res += f"\nПорт {line + 1}: {'включен' if result[0][line] == '1' else 'выключен'}, {result[1][line]} хостов"
                        bot.send_message(message.chat.id, f"У хоста {mess[1]} {model} следующие настройки:{res}")

                    # Если для указанной модели нет snmp - выводим это сообщение
                    except KeyError:
                        bot.send_message(message.chat.id, f"Модель {dlink[0]} пока недоступна для опроса")

            # Если хост недоступен - выводим следующее сообщение
            else:
                bot.send_message(message.chat.id, "Хост недоступен")

        # Справочная инфа о Влан
        elif mess[0] in Vlans and len(mess) == 1:
            bot.send_message(message.chat.id, 'Для вывода настроек vlans на длинке писать сообщение вида:\n'
                                              'Влан 172.23.230.2\n'
                                              'или\n'
                                              'Vlan 172.23.230.2\n\n'
                                              'Либо, если интересуют настройки конкретного vlan:\n'
                                              'Влан 172.23.230.2 111\n'
                                              'или\n'
                                              'Vlan 172.23.230.2 111\n\n'
                                              'Для некоторых редких моделей команда пока не работает.\n'
                                              'В выводе 0 - влана нет на порту, 1 - untagged, 2 - tagged.\n')

            # Дополнительная инфа для сотрудников офиса
            if message.from_user.id in Office_id.keys():
                bot.send_message(message.chat.id, 'Чтобы повесить на порт другой не тэгированный влан писать сообщение вида:\n'
                                                  'Влан 172.23.230.2 10 1001\n'
                                                  'или\n'
                                                  'Vlan 172.23.230.2 10 1001\n'
                                                  '(Vlan) (ip хоста) (порт) (влан)\n'
                                                  'Изменения сразу сохраняются в конфиг\n')

        # Если начинается на секур - проверяем, чтобы было 4 октета во второй части сообщения
        # и пробуем пингануть адрес
        elif mess[0] in Vlans and len(mess[1].split('.')) == 4:

            # Проверяем, доступен ли хост
            if ping_host(mess[1]):

                # Подключение к базе и запрос текущего оборудования
                # Возвращается ответ в вида вложенного списка [[модель, ip адрес, mac адрес], ...]
                cursor = connect_to_DB()
                dlinks = get_dlink(cursor)
                vlans = get_oid(cursor, 'Vlan')
                cursor.close()
                # Ищем модель длинка в базе
                for dlink in dlinks:
                    if mess[1] == dlink[1]:
                        model = dlink[0]
                        break

                # На случай встречи модели, для которой нет oid
                try:
                    # Вызываем функцию для получения настроек порта
                    result = get_vlan(mess[1], model, vlans[model])

                # Если для указанной модели нет snmp - выводим это сообщение
                except KeyError:
                    bot.send_message(message.chat.id, f"Устройство {mess[1]} пока недоступно для опроса")

                # Если для указанного адреса не нашлась модель - идём в эту ветку
                except NameError:

                    # Если длинк не нашёлся среди магазинных - проверяем, не был ли это запрос от офисных админов и ищем среди офисных длинков
                    if message.from_user.id in Office_id.keys():

                        # Подключение к базе и запрос текущего оборудования
                        # Возвращается ответ в вида вложенного списка [[модель, ip адрес, mac адрес], ...]
                        cursor = connect_to_DB()
                        dlinks = get_office_dlink(cursor)
                        save = get_oid(cursor, 'save_conf')
                        cursor.close()

                        # Ищем модель длинка в базе
                        for dlink in dlinks:
                            if mess[1] == dlink[1]:
                                model = dlink[0]
                                break

                        # На случай встречи модели, для которой нет oid
                        try:

                            # Проверяем, не было ли это запросом о перебросе порта
                            if len(mess) == 4:

                                # Если было - выполняем запрос
                                result = set_change_untag_port_vlan(mess[1], model, vlans[model], save[model], int(mess[3]), int(mess[2]))
                                bot.send_message(message.chat.id, result if result else "Что-то пошло не так...")

                            # Если запрос от сетевика и нужно повесить тэг - идём сюда
                            elif len(mess) == 5 and mess[4] == 'тэг' and str(message.from_user.id) in CAP:

                                # Если было - выполняем запрос
                                result = set_change_tag_port_vlan(mess[1], model, vlans[model], save[model], int(mess[3]), int(mess[2]))
                                bot.send_message(message.chat.id, result if result else "Что-то пошло не так...")

                            else:
                                # Вызываем функцию для получения настроек порта
                                result = get_vlan(mess[1], model, vlans[model])

                        # Если для указанной модели нет snmp - выводим это сообщение
                        except KeyError:
                            bot.send_message(message.chat.id, f"Устройство {mess[1]} пока недоступно для опроса")
                        # Если для указанного адреса не нашлась модель - выводим это сообщение
                        except NameError:
                            bot.send_message(message.chat.id, f"С адресом {mess[1]} не работаю!")

                    # Если нет - выводим сообщение
                    else:
                        bot.send_message(message.chat.id, f"С адресом {mess[1]} не работаю!")

                # Смотрим на длину сообщения и действуем исходя из этого
                # Если в сообщении три части - проверяем, является ли третья числом
                if len(mess) == 3:
                    if mess[2].isdigit():

                        # Идём по списку с вланами и проверяем, нашёлся ли указанный номер
                        for line in result:
                            if mess[2] == line[1]:
                                # Если нашёлся - выводим его настройки
                                bot.send_message(message.chat.id, 
                                                 f"У хоста {mess[1]} {model} влан {line[0]} с номером {line[1]} {'включен' if line[3] == '1' else 'выключен'}, "
                                                 f"настройки портов:\n{line[2]}")
                    else:
                        bot.send_message(message.chat.id, f"Вводи номер влана корректно!")

                # Если введено два слова, выводим полный список вланов
                elif len(mess) == 2:
                    res = ''
                    for line in result:
                        res += f"\n\nВлан {line[0]} с номером {line[1]} {'включен' if line[3] == '1' else 'выключен'}, настройки портов:\n{line[2]}"
                    bot.send_message(message.chat.id, f"У хоста {mess[1]} {model} следующие настройки:\n{res}")

            # Если хост недоступен - выводим следующее сообщение
            else:
                bot.send_message(message.chat.id, "Хост недоступен")

        # Справочная инфа о Секур
        elif mess[0] in Ports and len(mess) == 1:
            bot.send_message(message.chat.id, 'Для проверки активных портов на роутере писать сообщение вида:\n'
                                              'Порты 172.23.230.1\n'
                                              'или\n'
                                              'Ports 172.23.230.1\n')

        # Если начинается на порты - проверяем, чтобы во второй части сообщения было 4 октета
        elif mess[0] in Ports and len(mess[1].split('.')) == 4:

            # Проверяем, доступен ли хост
            if ping_host(mess[1]):

                # Подключаемся к базе и делаем запрос модели по ip
                cursor = connect_to_DB()
                result = cursor.execute(f"SELECT Model FROM Routers WHERE IP = '{mess[1]}'")
                # Смотрим что в результате и в зависимости от этого обращаемся к одной из функций
                try:
                    model = next(result)[0]
                    if 'ZyWALL' in model:
                        result = get_ports_zywall(mess[1], model)
                    else:
                        reuslt = get_ports_mikrotik(mess[1])
                    # Если ответ вернулся - создаём временную переменную
                    if result:

                        # Выводим полученную информацию
                        bot.send_message(message.chat.id, f"На магазе {mess[1]}:\nАктивных портов: {result[0]};\nИз них WAN :{result[1]}")
                        # Закрываем соединение с базой
                        cursor.close()

                    # Если в ответе функции False - выводим инфо об этом
                    else:
                        bot.send_message(message.chat.id, f"На магазе {mess[1]} что-то пошло не так")
                        cursor.close()

                # Если в базе не нашлась модель роутера - выводим следующее сообщение и закрываем соединение с базой
                except StopIteration:
                    bot.send_message(message.chat.id, "Не знаю такой роутер")
                    cursor.close()

            # Если хост недоступен - выводим следующее сообщение
            else:
                bot.send_message(message.chat.id, "Хост недоступен")

        # Рассылка всем пользователям, добавленным в одобренные
        elif mess[0] == 'рассылка' and str(message.from_user.id) in CAP:
            for line in Good_id.keys():
                bot.send_message(line, message.text[8:])

        # Рассылка всем пользователям, добавленным в одобренные
        elif mess[0] == 'рассылка_офис' and str(message.from_user.id) in CAP:
            for line in Good_id.keys():
                bot.send_message(line, message.text[13:])


        # Заглушка на случай если сообщение не прошло в остальные ветки
        else:
            bot.send_message(message.chat.id, Answers[randint(0, 4)])

    # Если пользователя нет в числе проверенных выводим сообщение и добавляем его в лог-файл
    else:
        bot.send_message(message.chat.id, f'{message.from_user.id}, я тебя не знаю!')
        with open ('bot_unknown.log', 'a') as f:
            print(f"{date_sms} писал {message.from_user.id} {message.from_user.username} {message.from_user.first_name} {message.from_user.last_name} сообщение {message.text}", file=f)




if __name__ == '__main__':

    bot.infinity_polling()
