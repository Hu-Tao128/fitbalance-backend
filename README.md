# FitBalance Backend

API backend para una app de nutricion enfocada en pacientes y nutriologos. El proyecto esta construido con Node.js + Express + TypeScript, usa MongoDB (Mongoose) y ahora tiene una arquitectura de capas organizada.

## Stack tecnico

- **Runtime:** Node.js 20
- **Framework:** Express
- **Lenguaje:** TypeScript (strict mode)
- **Base de datos:** MongoDB Atlas (Mongoose)
- **HTTP client:** Axios
- **Fechas/Zona horaria:** Luxon (`America/Tijuana`)
- **Correo:** Nodemailer
- **Seguridad de contrasenas:** bcryptjs
- **Despliegue:** Docker + Fly.io

## Arquitectura

El proyecto sigue una **Arquitectura de Capas**:

```
src/
├── index.ts              # Entry point (server bootstrap)
├── app.ts                # Configuracion Express
├── config/
│   └── env.ts           # Variables de entorno
├── models/              # Modelos Mongoose
│   ├── Patient.ts
│   ├── Food.ts
│   ├── WeeklyPlan.ts
│   ├── DailyMealLog.ts
│   ├── PatientMeal.ts
│   ├── Appointment.ts
│   ├── Nutritionist.ts
│   ├── PasswordResetToken.ts
│   └── index.ts
├── types/                # Tipos e interfaces
│   └── index.ts
├── services/            # Logica de negocio
│   ├── dateService.ts
│   ├── emailService.ts
│   ├── fatSecretService.ts
│   ├── nutritionixService.ts
│   ├── nutritionCalculator.ts
│   └── index.ts
├── controllers/         # Controladores
│   ├── authController.ts
│   ├── patientController.ts
│   ├── foodController.ts
│   ├── weeklyPlanController.ts
│   ├── dailyMealLogController.ts
│   ├── patientMealController.ts
│   ├── appointmentController.ts
│   ├── nutritionistController.ts
│   └── index.ts
└── routes/              # Rutas Express
    ├── authRoutes.ts
    ├── patientRoutes.ts
    ├── foodRoutes.ts
    ├── weeklyPlanRoutes.ts
    ├── dailyMealLogRoutes.ts
    ├── patientMealRoutes.ts
    ├── appointmentRoutes.ts
    ├── nutritionistRoutes.ts
    └── index.ts
```

## Instalacion

```bash
yarn install
```

## Variables de entorno

Crea un archivo `.env` con las siguientes variables:

```env
MONGODB_URI=mongodb+srv://...
FATSECRET_CONSUMER_KEY=...
FATSECRET_CONSUMER_SECRET=...
NUTRITIONIX_APP_ID=...
NUTRITIONIX_APP_KEY=...
EMAIL_SERVICE=gmail
EMAIL_USER=...
EMAIL_PASS=...
PORT=3000
```

## Scripts

```bash
yarn dev          # Desarrollo con hot-reload
yarn build        # Compilar TypeScript
yarn start        # Ejecutar produccion
yarn test         # Run tests
yarn test:watch   # Tests en modo watch
yarn test:coverage # Coverage report
yarn lint         # ESLint
yarn lint:fix     # ESLint auto-fix
yarn format       # Prettier formatter
```

## Funcionalidades principales

- Login de pacientes y consulta de perfil.
- Recuperacion de contrasena por codigo enviado por email.
- Busqueda de alimentos con Nutritionix.
- Gestion de plan semanal y consulta de plan del dia.
- Registro diario de comidas.
- CRUD de comidas personalizadas por paciente.
- Consulta de citas de pacientes.
- Consulta de datos de nutriologo.

## Endpoints principales

### Auth
- `POST /login`
- `POST /send-reset-code`
- `PUT /patients/change-password`

### Pacientes
- `GET /user/:username`
- `PUT /patient/:id`

### Alimentos
- `POST /search-food`
- `GET /api/food`

### Plan Semanal
- `GET /weeklyplan/latest/:patient_id`
- `GET /weeklyplan/daily/:patient_id`

### Daily Meal Logs
- `GET /daily-nutrition`
- `GET /daily-meal-logs/today/:patient_id`
- `GET /daily-meal-logs/all/:patient_id`
- `GET /daily-meal-logs/by-date`
- `POST /daily-meal-logs/add-meal`
- `POST /daily-meal-logs/add-weekly-meal`
- `POST /DailyMealLogs/add-custom-meal`
- `DELETE /daily-meal-logs/:logId/meals/:mealId`

### Comidas Personalizadas
- `POST /PatientMeals`
- `GET /PatientMeals/:patient_id`
- `PUT /PatientMeals/:meal_id`
- `DELETE /PatientMeals/:meal_id`

### Citas y Nutrilogo
- `GET /appointments/:patient_id`
- `GET /nutritionist/:id`

## Despliegue

### Docker

```bash
docker build -t fitbalance-backend .
docker run --env-file .env -p 3000:3000 fitbalance-backend
```

### Fly.io

```bash
fly deploy
```

## Testing

El proyecto incluye tests con Jest:

```bash
yarn test           # Run all tests
yarn test:coverage  # Coverage report
```

## Linting

```bash
yarn lint           # Check linting
yarn lint:fix       # Auto-fix issues
```

## Notas

- Todas las fechas usan la zona horaria `America/Tijuana`.
- La API mantiene compatibilidad con el frontend existente (rutas exactas).
