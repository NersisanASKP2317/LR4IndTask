# ============================================================
# БЛОК 1. ИМПОРТ БИБЛИОТЕК
# ============================================================

from flask import Flask, request, jsonify      # Flask — веб-фреймворк, request — обработка HTTP-запросов, jsonify — формирование JSON-ответов
from prometheus_client import Counter, Histogram, generate_latest, CONTENT_TYPE_LATEST  # метрики Prometheus
import time                                      # для измерения времени выполнения запросов

# ============================================================
# БЛОК 2. ИНИЦИАЛИЗАЦИЯ FLASK-ПРИЛОЖЕНИЯ
# ============================================================

app = Flask(__name__)                           # создание экземпляра Flask-приложения

# ============================================================
# БЛОК 3. НАСТРОЙКА МЕТРИК PROMETHEUS
# ============================================================

# Counter — счётчик (только увеличивается)
REQUEST_COUNT = Counter('http_requests_total', 'Total HTTP requests', ['method', 'endpoint', 'status'])
# Histogram — гистограмма распределения значений (время отклика)
REQUEST_DURATION = Histogram('http_request_duration_seconds', 'HTTP request duration', ['method', 'endpoint'])
# Счётчик заблокированных URL
BLOCKED_COUNT = Counter('ub167_blocked_total', 'Total blocked URLs')
# Счётчик разрешённых URL
ALLOWED_COUNT = Counter('ub167_allowed_total', 'Total allowed URLs')

# ============================================================
# БЛОК 4. КОНФИГУРАЦИОННЫЕ ДАННЫЕ (ЧЁРНЫЙ СПИСОК)
# ============================================================

# Список опасных доменов (при проверке URL блокируются)
BLACKLIST = ["bad-site.ru", "phishing.com", "malware.net", "exploit.com"]

# ============================================================
# БЛОК 5. ЭНДПОИНТ ДЛЯ МЕТРИК PROMETHEUS
# ============================================================

@app.route('/metrics', methods=['GET'])
def metrics():
    """Эндпоинт для сбора метрик Prometheus"""
    # generate_latest() — генерирует метрики в текстовом формате, понятном Prometheus
    return generate_latest(), 200, {'Content-Type': CONTENT_TYPE_LATEST}

# ============================================================
# БЛОК 6. ОСНОВНАЯ ЛОГИКА ПРОВЕРКИ URL (ЭНДПОИНТ /check)
# ============================================================

@app.route('/check', methods=['GET'])
def check_url():
    # ===== БЛОК 6.1. НАЧАЛО ИЗМЕРЕНИЯ ВРЕМЕНИ =====
    start_time = time.time()
    
    # ===== БЛОК 6.2. ПОЛУЧЕНИЕ ВХОДНЫХ ДАННЫХ =====
    url = request.args.get('file', '')           # получение параметра 'file' из GET-запроса
    
    # ===== БЛОК 6.3. ПРОВЕРКА НА ПУСТОЙ URL =====
    if not url:                                  # если URL не передан
        REQUEST_COUNT.labels(method='GET', endpoint='/check', status='error').inc()  # регистрация ошибки в метриках
        return jsonify({'blocked': False, 'message': 'No URL provided'})            # возврат JSON-ответа
    
    # ===== БЛОК 6.4. НОРМАЛИЗАЦИЯ URL =====
    url_lower = url.lower()                      # приведение к нижнему регистру (регистронезависимость)
    
    # ===== БЛОК 6.5. ФИЛЬТРАЦИЯ ПО ЧЁРНОМУ СПИСКУ =====
    blocked = False
    for pattern in BLACKLIST:                    # перебор доменов из чёрного списка
        if pattern in url_lower:                 # если опасный домен найден в URL
            blocked = True                       # устанавливаем флаг блокировки
            break                                 # прерываем цикл
    
    # ===== БЛОК 6.6. ИЗМЕРЕНИЕ ВРЕМЕНИ ВЫПОЛНЕНИЯ =====
    duration = time.time() - start_time          # вычисляем время отклика API
    REQUEST_DURATION.labels(method='GET', endpoint='/check').observe(duration)  # запись времени в гистограмму
    
    # ===== БЛОК 6.7. ФОРМИРОВАНИЕ ОТВЕТА И ОБНОВЛЕНИЕ МЕТРИК =====
    if blocked:                                   # если URL опасный
        BLOCKED_COUNT.inc()                       # увеличиваем счётчик блокировок
        REQUEST_COUNT.labels(method='GET', endpoint='/check', status='blocked').inc()
        return jsonify({'url': url, 'blocked': True, 'message': f'Blocked: dangerous site'})
    else:                                         # если URL безопасный
        ALLOWED_COUNT.inc()                       # увеличиваем счётчик разрешений
        REQUEST_COUNT.labels(method='GET', endpoint='/check', status='allowed').inc()
        return jsonify({'url': url, 'blocked': False, 'message': 'Passed: URL is safe'})

# ============================================================
# БЛОК 7. ЗАПУСК ПРИЛОЖЕНИЯ
# ============================================================

if __name__ == '__main__':
    # host='0.0.0.0' — слушаем все сетевые интерфейсы
    # port=5000 — порт, на котором работает Flask
    app.run(host='0.0.0.0', port=5000)
