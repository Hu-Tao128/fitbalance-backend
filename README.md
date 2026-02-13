# FitBalance Backend

API backend para una app de nutricion enfocada en pacientes y nutriologos. El proyecto esta construido con Node.js + Express + TypeScript, usa MongoDB (Mongoose) y concentra en un solo servicio funcionalidades de autenticacion, planes semanales, logs diarios de comidas, alimentos personalizados, citas y recuperacion de contrasena por correo.

## Stack tecnico

- **Runtime:** Node.js 20
- **Framework:** Express
- **Lenguaje:** TypeScript
- **Base de datos:** MongoDB Atlas (Mongoose)
- **HTTP client:** Axios
- **Fechas/Zona horaria:** Luxon (`America/Tijuana`)
- **Correo:** Nodemailer
- **Seguridad de contrasenas:** bcryptjs
- **Despliegue:** Docker + Fly.io (config incluido)

## Funcionalidades principales

- Login de pacientes y consulta de perfil.
- Recuperacion de contrasena por codigo enviado por email.
- Busqueda de alimentos con Nutritionix (`/search-food`).
- Lectura de alimentos guardados en BD (`/api/food`).
- Gestion de plan semanal y consulta de plan del dia.
- Registro diario de comidas (agregar comida semanal, personalizada o alimento suelto).
- Recalculo de macros/calorias por dia.
- CRUD de comidas personalizadas por paciente (`PatientMeals`).
- Consulta de citas de pacientes.
- Consulta de datos de nutriologo.

## Variables de entorno

Variables obligatorias detectadas en el codigo:

- `MONGODB_URI`
- `FATSECRET_CONSUMER_KEY`
- `FATSECRET_CONSUMER_SECRET`
- `NUTRITIONIX_APP_ID`
- `NUTRITIONIX_APP_KEY`

Variables usadas para envio de correo:

- `EMAIL_SERVICE`
- `EMAIL_USER`
- `EMAIL_PASS`

Variables de ejecucion:

- `PORT` (opcional, por defecto `3000`)

Ejemplo minimo de `.env`:

```env
MONGODB_URI=mongodb+srv://...
FATSECRET_CONSUMER_KEY=...
FATSECRET_CONSUMER_SECRET=...
NUTRITIONIX_APP_ID=...
NUTRITIONIX_APP_KEY=...
EMAIL_SERVICE=gmail
EMAIL_USER=tu-correo@dominio.com
EMAIL_PASS=tu-password-o-app-password
PORT=3000
```

## Instalacion y ejecucion

```bash
npm install
npm run dev
```

Scripts disponibles:

- `npm run dev`: arranque en desarrollo con recarga (`ts-node-dev`).
- `npm run build`: compila TypeScript a `dist/`.
- `npm run start`: ejecuta el build compilado.

## Estructura del proyecto

```text
.
├── src/
│   └── index.ts        # API completa (modelos + endpoints)
├── dist/               # salida compilada
├── Dockerfile
├── fly.toml
├── package.json
└── tsconfig.json
```

## Endpoints principales

> Nota: el proyecto mezcla rutas en minusculas y PascalCase. Conviene mantener exactamente los paths actuales desde el frontend.

### Auth y perfil

- `POST /login`
- `GET /user/:username`
- `PUT /patient/:id`
- `PUT /patients/change-password`
- `POST /send-reset-code`

### Alimentos y busqueda

- `POST /search-food`
- `GET /api/food`

### Plan semanal

- `GET /weeklyplan/latest/:patient_id`
- `GET /weeklyplan/daily/:patient_id`

### Daily meal logs

- `GET /daily-nutrition`
- `GET /daily-meal-logs/today/:patient_id`
- `GET /daily-meal-logs/all/:patient_id`
- `GET /daily-meal-logs/by-date`
- `POST /daily-meal-logs/add-meal`
- `POST /daily-meal-logs/add-weekly-meal`
- `POST /DailyMealLogs/add-weekly-meal`
- `POST /DailyMealLogs/add-custom-meal`
- `POST /dailymeallogs/add-food`
- `DELETE /daily-meal-logs/:logId/meals/:mealId`

### Comidas personalizadas

- `POST /PatientMeals`
- `GET /PatientMeals/:patient_id`
- `PUT /PatientMeals/:meal_id`
- `DELETE /PatientMeals/:meal_id`

### Citas y nutriologo

- `GET /appointments/:patient_id`
- `GET /nutritionist/:id`

## Despliegue

El repositorio incluye:

- `Dockerfile` multietapa (build y runtime).
- `fly.toml` para Fly.io (`app = fitbalance-backend`).

Comandos tipicos:

```bash
npm run build
npm run start
```

o con Docker:

```bash
docker build -t fitbalance-backend .
docker run --env-file .env -p 3000:3000 fitbalance-backend
```

## Observaciones tecnicas

- Toda la logica vive actualmente en `src/index.ts` (archivo monolitico).
- Se usan multiples modelos Mongoose en el mismo archivo (`Patient`, `Food`, `WeeklyPlan`, `DailyMealLog`, `PatientMeal`, `Appointment`, `Nutritionist`, `PasswordResetToken`).
- Hay logica importante de fechas ajustada a zona horaria `America/Tijuana`.
- Existen rutas similares con diferencias de casing (`/daily-meal-logs/...` vs `/DailyMealLogs/...`).

## Recomendaciones de mejora

- Separar por capas/modulos (`routes`, `controllers`, `services`, `models`).
- Estandarizar naming de endpoints (kebab-case consistente).
- Agregar validacion formal de request bodies (por ejemplo, Zod/Joi).
- Incorporar tests de integracion para rutas criticas.
- Incluir `README` de API con ejemplos de request/response por endpoint.
