# Используем официальный образ Python 3.10
FROM python:3.10-slim

# Устанавливаем зависимости системы
RUN apt-get update && apt-get install -y \
    gcc \
    libldap2-dev \
    libsasl2-dev \
    libssl-dev \
    default-jdk \
    && rm -rf /var/lib/apt/lists/*

# Устанавливаем рабочую директорию
WORKDIR /app

# Копируем файл requirements.txt в контейнер
COPY requirements.txt .

# Устанавливаем зависимости проекта
RUN pip install --no-cache-dir -r requirements.txt

# Копируем все файлы проекта в контейнер
COPY . .

EXPOSE 1389

# Устанавливаем точку входа
CMD ["python", "server_emulator.py"]
