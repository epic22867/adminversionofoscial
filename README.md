# 🚀 Railway Full Stack

Node.js + Express + PostgreSQL. Пользователи, посты, настройки.

## Структура

```
├── public/
│   └── index.html     ← весь фронтенд (HTML + CSS + JS)
├── server.js          ← Express API + подключение к БД
├── package.json
├── railway.toml
├── .env.example       ← пример переменных окружения
└── .gitignore
```

## API

| Метод | URL | Описание |
|-------|-----|----------|
| GET | /api/status | Статус сервера |
| POST | /api/register | Регистрация |
| POST | /api/login | Вход |
| POST | /api/logout | Выход |
| GET | /api/me | Текущий пользователь |
| GET | /api/posts | Все посты |
| POST | /api/posts | Создать пост |
| DELETE | /api/posts/:id | Удалить пост |
| GET | /api/settings | Настройки |
| POST | /api/settings | Сохранить настройки |

## Деплой на Railway

1. Залей код на GitHub
2. [railway.app](https://railway.app) → **New Project → Deploy from GitHub**
3. В проекте нажми **+ New → Database → PostgreSQL**
4. Railway автоматически добавит `DATABASE_URL` в переменные
5. Добавь вручную: `SESSION_SECRET=любая-случайная-строка` и `NODE_ENV=production`

Всё, сайт работает!
