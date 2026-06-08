import os
proxy_token = os.environ.get('PROXY_AUTH_TOKEN')
blacklist_key = os.environ.get('BLACKLIST_API_KEY')
antivirus_key = os.environ.get('ANTIVIRUS_API_KEY')
docker_token = os.environ.get('DOCKER_REGISTRY_TOKEN')
print("Секретные ключи модуля Контейнера: ")
print("PROXY_AUTH_TOKEN", proxy_token)
print("BLACKLIST_API_KEY", blacklist_key)
print("ANTIVIRUS_API_KEY", antivirus_key)
print("DOCKER_REGISTRY_TOKEN", docker_token)

# main.py для Replit
# Эмулятор контейнера защиты от УБИ.167 (нефтегазовая компания)

import json
from datetime import datetime
from collections import defaultdict
import matplotlib.pyplot as plt
WHITELIST = [
    "google.com", "yandex.ru", "youtube.com", "github.com",
    "stackoverflow.com", "neverssl.com", "python.org", "microsoft.com",
    "gubkin.ru", "minenergo.gov.ru", "rosneft.ru", "gazprom.ru"
]

BLACKLIST = [
    "bad-site.ru", "phishing.com", "malware.net", "drive-by-download.ru",
    "exploit.com", "crack.ru", "hack-tools.org", "fake-update.ru", "test-block1.ru", "changes-rep.com"
]

USERS = {
    "Геолог Иванов": "Геология",
    "Геолог Петрова": "Геология",
    "Бухгалтер Смирнова": "Бухгалтерия",
    "Тендерщик Козлов": "Тендерный отдел",
    "Инженер Морозов": "Инженерия",
    "Секретарь Васильева": "Администрация",
    "Начальник Волков": "Руководство",
    "IT специалист Новиков": "IT отдел",
    "Аудитор Пономарева": "Безопасность",
    "Лаборанат Соколовский": "Лаборатория",
}

MOCK_REQUESTS = [
    # Безопасные запросы
    ("Геолог Иванов", "https://google.com/search?q=месторождение", None),
    ("Геолог Иванов", "https://rosneft.ru", None),
    ("Геолог Петрова", "https://gazprom.ru", None),
    ("Геолог Петрова", "https://yandex.ru", None),
    ("Бухгалтер Смирнова", "https://google.com", "report.xlsx"),
    ("Тендерщик Козлов", "https://gubkin.ru", None),
    ("Тендерщик Козлов", "https://exploit.com", None),
    ("Инженер Морозов", "https://crack.ru", "setup.exe"),
    ("Инженер Морозов", "https://github.com", None),
    ("Секретарь Васильева", "https://yandex.ru/news", None),
    ("Начальник Волков", "https://google.com/maps", None),
    ("IT специалист Новиков", "https://stackoverflow.com", None),
    ("IT специалист Новиков", "https://python.org", "script.py"),
    # Опасные запросы
    ("Геолог Иванов", "http://phishing.com", None),
    ("Геолог Иванов", "https://bad-site.ru", "keygen.exe"),
    ("Геолог Петрова", "http://malware.net", None),
    ("Бухгалтер Смирнова", "https://drive-by-download.ru", "payment.exe"),
    ("Тендерщик Козлов", "http://exploit.com", None),
    ("Инженер Морозов", "https://crack.ru", "keygen.exe"),
    ("Секретарь Васильева", "http://hack-tools.org", None),
    ("Начальник Волков", "https://fake-update.ru", None),
    # Повторы для статистики
    ("Геолог Иванов", "https://google.com", None),
    ("Бухгалтер Смирнова", "https://yandex.ru", None),
    ("Тендерщик Козлов", "http://bad-site.ru", None),
    ("Инженер Морозов", "https://github.com", None),
    ("Начальник Волков", "https://phishing.com", None),
    ("Геолог Петрова", "https://google.com", None),
    ("IT специалист Новиков", "https://neverssl.com", None),
    ("Аудитор Пономарева", "https://test-block1.ru", None),
    ("Аудитор Пономарева", "https://changes-rep.com", "virus.exe"),
    ("Лаборанат Соколовский", "https://google.com", "report.xlsx"),
    ("Лаборанат Соколовский", "https://bad-site.ru", None),
    ("Геолог Иванов", "https://test-block1.ru", None),
    ("Стажер Сидоров", "https://google.com", None),  # пользователь не в USERS
]

def is_blocked(url):
    url_lower = url.lower()
    for domain in WHITELIST:
        if domain in url_lower:
            return False, None
    for domain in BLACKLIST:
        if domain in url_lower:
            return True, domain
    return False, None

def check_file(filename):
    if not filename:
        return True, None
    dangerous = [".exe", ".scr", ".bat", ".dll", ".vbs", ".ps1", ".msi", ".jar"]
    for ext in dangerous:
        if filename.lower().endswith(ext):
            return False, f"опасное расширение {ext}"
    return True, None

results = []
stats_hourly = defaultdict(lambda: {"заблокировано": 0, "разрешено": 0})
stats_user = defaultdict(lambda: {"заблокировано": 0, "разрешено": 0})
stats_role = defaultdict(lambda: {"заблокировано": 0, "разрешено": 0})
unique_users = set()
for user, url, file in MOCK_REQUESTS:
    unique_users.add(user)
    blocked, domain = is_blocked(url)
    file_ok, file_reason = check_file(file)

    if blocked:
        status = "ЗАБЛОКИРОВАНО"
        reason = f"домен {domain} в черном списке"
    elif not file_ok:
        status = "ЗАБЛОКИРОВАНО"
        reason = file_reason
    else:
        status = "РАЗРЕШЕНО"
        reason = "все проверки пройдены"

    hour = datetime.now().strftime("%H:00")
    if status == "ЗАБЛОКИРОВАНО":
        stats_hourly[hour]["заблокировано"] += 1
        stats_user[user]["заблокировано"] += 1
        stats_role[USERS[user]]["заблокировано"] += 1
    else:
        stats_hourly[hour]["разрешено"] += 1
        stats_user[user]["разрешено"] += 1
        stats_role[USERS[user]]["разрешено"] += 1

    results.append({
        "time": datetime.now().strftime("%H:%M:%S"),
        "user": user,
        "url": url[:55],
        "file": file or "-",
        "status": status,
        "reason": reason
    })

total = len(results)
blocked_cnt = sum(1 for r in results if r["status"] == "ЗАБЛОКИРОВАНО")
allowed_cnt = total - blocked_cnt

print("УБИ.167 КОНТЕЙНЕР ЗАЩИТЫ")
print("Нефтегазовая компания")


print("\n[ЖУРНАЛ ЛОГОВ]\n")
print(f"{'N':<3} {'ВРЕМЯ':<8} {'ПОЛЬЗОВАТЕЛЬ':<18} {'URL':<45} {'СТАТУС':<10} {'ПРИЧИНА':<25}")


for i, r in enumerate(results, 1):
    print(f"{i:<3} {r['time']:<8} {r['user']:<18} {r['url']:<45} {r['status']:<10} {r['reason']:<25}")



print("\n[ОБЩАЯ СТАТИСТИКА]")
print(f"  Всего запросов:                      {total}")
print(f"  РАЗРЕШЕНО:                           {allowed_cnt}")
print(f"  ЗАБЛОКИРОВАНО:                       {blocked_cnt}")
print(f"  Доля блокировок:                     {round(blocked_cnt/total*100, 1)}%")
print(f"  Уникальных пользователей:            {len(unique_users)}")
print(f"  Заблокировано файлов: {sum(1 for r in results if r['file'] != '-' and r['status'] == 'ЗАБЛОКИРОВАНО')}")
print("\n[СТАТИСТИКА ПО ПОЛЬЗОВАТЕЛЯМ]")
print(f"{'Пользователь':<20} {'Отдел':<16} {'OK':<5} {'БЛОК':<5} {'ВСЕГО':<6} {'НАДЕЖНОСТЬ':<10}")


for user, role in USERS.items():
    allowed = stats_user[user]["разрешено"]
    blocked = stats_user[user]["заблокировано"]
    total_u = allowed + blocked
    reliability = round((1 - blocked / total_u) * 100, 1) if total_u > 0 else 100
    print(f"{user:<20} {role:<16} {allowed:<5} {blocked:<5} {total_u:<6} {reliability}%")


print("\n[СТАТИСТИКА ПО ОТДЕЛАМ]")

print(f"{'Отдел':<18} {'OK':<5} {'БЛОК':<5} {'ВСЕГО':<6} {'УРОВЕНЬ РИСКА':<15}")


for role, data in stats_role.items():
    allowed = data["разрешено"]
    blocked = data["заблокировано"]
    total_r = allowed + blocked
    risk = round(blocked / total_r * 100, 1) if total_r > 0 else 0
    bar = "." * 7
    print(f"{role:<18} {allowed:<5} {blocked:<5} {total_r:<6} {bar} {risk}%")



plt.figure(figsize=(7, 7))
plt.pie([blocked_cnt, allowed_cnt], 
        labels=[f'Заблокировано\n{blocked_cnt}', f'Разрешено\n{allowed_cnt}'],
        colors=['#e74c3c', '#2ecc71'],
        autopct='%1.1f%%',
        shadow=True,
        explode=(0.05, 0))
plt.title('Распределение запросов')
plt.savefig('chart_pie.png')
plt.close()

roles = list(stats_role.keys())
role_blocked = [stats_role[r]["заблокировано"] for r in roles]
role_allowed = [stats_role[r]["разрешено"] for r in roles]

plt.figure(figsize=(9, 5))
x = range(len(roles))
plt.bar([i - 0.2 for i in x], role_blocked, width=0.4, label='Заблокировано', color='#e74c3c')
plt.bar([i + 0.2 for i in x], role_allowed, width=0.4, label='Разрешено', color='#2ecc71')
plt.xlabel('Отдел')
plt.ylabel('Запросы')
plt.title('Статистика по отделам')
plt.xticks(x, roles, rotation=15)
plt.legend()
plt.grid(True, alpha=0.3, axis='y')
plt.tight_layout()
plt.savefig('chart_departments.png')
plt.close()

plt.figure(figsize=(10,6))
users_list = []
reliability_list = []
blocked_count_list = []

for user, role in USERS.items():
    blocked = stats_user[user]["заблокировано"]
    total_u = stats_user[user]["разрешено"] + blocked
    reliability = round((1 - blocked / total_u) * 100, 1) 
    users_list.append(user)
    reliability_list.append(reliability)
    blocked_count_list.append(blocked)

sorted_data = sorted(zip(reliability_list, users_list, blocked_count_list))
reliability_list, users_list, blocked_count_list = zip(*sorted_data)

colors = ['#e74c3c' if r < 70 else '#f39c12' if r < 90 else '#2ecc71' for r in reliability_list]
plt.barh(users_list, reliability_list, color=colors)
plt.xlabel('Надежность (%)')
plt.ylabel('Пользователь')
plt.title('Надежность сотрудников')
plt.xlim(0,100)
plt.grid(True, alpha=0.3, axis = 'x')

for i, (user, rel, blocked)  in enumerate(zip(users_list, reliability_list, blocked_count_list)):
    plt.text(rel + 1, i, f"{rel}% ({blocked} блок)", va='center', fontsize = 9)

plt.tight_layout()
plt.savefig('chart_users_reliability.png')
plt.close()

