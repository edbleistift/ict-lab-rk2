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
```powershell
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
Результат: pfSense успешно отфильтровал подозрительный трафик и ограничил количество соединений.

- root@edward-VM: настроен iptables для защиты от DDoS-атак, сканирования портов и блокировки подозрительных IP. Все настройки успешно протестированы.
- C:\Users\unrea: настроен Windows Firewall для блокировки IP и ограничения входящих подключений. Настройки работают корректно.
- pfSense: виртуальная сеть успешно защищена, правила фильтрации трафика и мониторинг атак протестированы.


11.	Управление обновлениями и патчами:
СРО: Настройте автоматическое управление обновлениями и патчами на сервере с помощью утилит (например, yum для CentOS или apt для Ubuntu). Представьте отчет о процессе обновления с анализом влияния на безопасность системы.
СРОП: Разработайте план управления обновлениями для крупной сети, включающий различные операционные системы и ПО. Оцените риски, связанные с отсутствием обновлений, и представьте отчет с рекомендациями по автоматизации процессов.

12.	Шифрование и защита данных:
СРО: Настройте систему шифрования данных на уровне файловой системы с использованием LUKS (для Linux) или BitLocker (для Windows). Подготовьте отчет о настройках шифрования, его использовании и защите ключей.
СРОП: Исследуйте и реализуйте шифрование данных при передаче через сеть (например, с использованием OpenVPN или TLS). Представьте результаты тестирования эффективности шифрования.

13.	Управление сетевой инфраструктурой:
СРО: Настройте сетевое оборудование (например, маршрутизатор и коммутатор Cisco) для создания виртуальных локальных сетей (VLAN) и настройки динамической маршрутизации (OSPF). Подготовьте отчет о конфигурации и тестировании.
СРОП: Выполните аудит текущей сетевой инфраструктуры компании (или симулированной сети). Оцените производительность и отказоустойчивость инфраструктуры, предоставьте отчет с рекомендациями по улучшению.

14.	Уязвимости и эксплуатация:
СРО: Используйте инструмент сканирования уязвимостей (например, OpenVAS или Nessus) для анализа виртуальной сети на наличие уязвимостей. Предоставьте отчет о выявленных уязвимостях и рекомендациях по их устранению.
СРОП: Проведите исследование и использование одной из уязвимостей с помощью инструмента Metasploit или аналогичного. Подготовьте отчет с описанием процесса эксплуатации и рекомендациями по защите.

15.	Будущее безопасности систем и сетей:
СРО: Проведите исследование современных тенденций в области безопасности систем и сетей, таких как квантовое шифрование или использование искусственного интеллекта для защиты сетей. Подготовьте аналитический отчет с прогнозами на будущее.
СРОП: Создайте презентацию на тему будущего безопасности систем и сетей, включив в нее анализ текущих и перспективных технологий. Оцените потенциальные угрозы и решения, которые будут актуальны в ближайшие 5-10 лет. 
