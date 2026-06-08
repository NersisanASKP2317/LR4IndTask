
#!/bin/bash

# Скрипт развертывания контейнера защиты УБИ.167

echo "УБИ.167 - Контейнер защиты от заражения сайтов"
echo "Нефтегазовая компания"
echo ""

# Проверка наличия Python
if ! command -v python3 &> /dev/null; then
    echo "Ошибка: Python3 не установлен"
    exit 1
fi

# Проверка наличия файла index.html
if [ ! -f "index.html" ]; then
    echo "Ошибка: Файл index.html не найден"
    exit 1
fi

echo "Файл index.html найден"

# Проверка доступности интернета для CDN
if curl -s --head https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js | head -n 1 | grep -q "200\|301\|302"; then
    echo "Интернет доступен"
else
    echo "Предупреждение: интернет может быть недоступен, графики могут не загрузиться"
fi

PORT=${PORT:-8080}
echo "Запуск на порту $PORT"

python3 -m http.server $PORT
