from flask import Flask, request, jsonify
from prometheus_client import Counter, Histogram, generate_latest, CONTENT_TYPE_LATEST
import time

app = Flask(__name__)

# ============ МЕТРИКИ PROMETHEUS ============
REQUEST_COUNT = Counter('http_requests_total', 'Total HTTP requests', ['method', 'endpoint', 'status'])
REQUEST_DURATION = Histogram('http_request_duration_seconds', 'HTTP request duration', ['method', 'endpoint'])
BLOCKED_COUNT = Counter('ub167_blocked_total', 'Total blocked URLs')
ALLOWED_COUNT = Counter('ub167_allowed_total', 'Total allowed URLs')
# ============================================

# Чёрный список доменов
BLACKLIST = ["bad-site.ru", "phishing.com", "malware.net", "exploit.com"]

@app.route('/metrics', methods=['GET'])
def metrics():
    """Эндпоинт для сбора метрик Prometheus"""
    return generate_latest(), 200, {'Content-Type': CONTENT_TYPE_LATEST}

@app.route('/check', methods=['GET'])
def check_url():
    start_time = time.time()
    
    url = request.args.get('file', '')
    if not url:
        REQUEST_COUNT.labels(method='GET', endpoint='/check', status='error').inc()
        return jsonify({'blocked': False, 'message': 'No URL provided'})
    
    url_lower = url.lower()
    blocked = False
    
    for pattern in BLACKLIST:
        if pattern in url_lower:
            blocked = True
            break
    
    duration = time.time() - start_time
    REQUEST_DURATION.labels(method='GET', endpoint='/check').observe(duration)
    
    if blocked:
        BLOCKED_COUNT.inc()
        REQUEST_COUNT.labels(method='GET', endpoint='/check', status='blocked').inc()
        return jsonify({'url': url, 'blocked': True, 'message': f'Blocked: dangerous site'})
    else:
        ALLOWED_COUNT.inc()
        REQUEST_COUNT.labels(method='GET', endpoint='/check', status='allowed').inc()
        return jsonify({'url': url, 'blocked': False, 'message': 'Passed: URL is safe'})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)