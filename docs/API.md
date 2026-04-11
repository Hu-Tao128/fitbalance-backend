# API Documentation - FitBalance Backend

**Nota:** Las rutas del backend no tienen prefijo `/api`. El frontend usa un cliente axios que añade ese prefijo globalmente.

---

## Autenticación

### Header de Autorización

Todos los endpoints protegidos (excepto `/login` y `/send-reset-code`) requieren un token JWT en el header:

```
Authorization: Bearer <token_jwt>
```

**Ejemplo:**

```http
GET /user/juan123
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

**Respuestas de error comunes:**

- `401 Unauthorized`: Token no proporcionado
- `403 Forbidden`: Token inválido o expirado

---

## Endpoints

---

### 1. Autenticación

#### POST /login

Iniciar sesión y obtener token JWT.

**Body:**

```json
{
  "username": "string",
  "password": "string"
}
```

**Respuesta exitosa:**

```json
{
  "message": "Login exitoso",
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "patient": {
    "_id": "...",
    "username": "juan123",
    "email": "juan@email.com",
    "name": "Juan Perez",
    ...
  }
}
```

**Nota:** El token expira en 24 horas.

---

#### POST /send-reset-code

Enviar código de recuperación de contraseña al correo.

**Body:**

```json
{
  "email": "string"
}
```

**Respuesta:**

```json
{
  "message": "Codigo de recuperacion enviado al correo del paciente."
}
```

---

#### PUT /patients/change-password

Cambiar contraseña del paciente. **Requiere autenticación.**

**Body:**

```json
{
  "patient_id": "string",
  "currentPassword": "string",
  "newPassword": "string"
}
```

**Respuesta:**

```json
{
  "message": "Contrasena actualizada con exito."
}
```

---

### 2. Pacientes

#### GET /user/:username

Obtener datos de un paciente por username. **Requiere autenticación.**

**Parámetros:**

- `username` (path): Username del paciente

**Respuesta:**

```json
{
  "_id": "...",
  "username": "juan123",
  "email": "juan@email.com",
  "name": "Juan Perez",
  "age": 30,
  "weight": 70,
  "height": 175,
  ...
}
```

---

#### PUT /patient/:id

Actualizar datos del paciente. **Requiere autenticación.**

**Parámetros:**

- `id` (path): ID del paciente

**Body:** Cualquier campo editable del paciente (excepto username y password)

**Respuesta:**

```json
{
  "message": "Perfil actualizado con exito",
  "patient": { ... }
}
```

---

### 3. Nutricionistas

#### GET /nutritionist/:id

Obtener datos de un nutricionista. **Requiere autenticación.**

**Parámetros:**

- `id` (path): ID del nutricionista

**Respuesta:**

```json
{
  "_id": "...",
  "name": "Dr. Maria Garcia",
  "email": "maria@clinica.com",
  "specialty": "Nutrición Clínica",
  ...
}
```

---

### 4. Alimentos

#### POST /search-food

Buscar alimentos en Nutritionix API. **Requiere autenticación.**

**Body:**

```json
{
  "query": "string"
}
```

**Respuesta:**

```json
{
  "source": "nutritionix",
  "results": [
    {
      "food_name": "Chicken breast",
      "serving_weight_grams": 100,
      "nf_calories": 165,
      "nf_protein": 31,
      "nf_total_carbohydrate": 0,
      "nf_total_fat": 3.6,
      ...
    }
  ]
}
```

---

#### GET /api/food

Obtener todos los alimentos de la base de datos. **Requiere autenticación.**

**Respuesta:**

```json
[
  {
    "_id": "...",
    "name": "Pollo",
    "portion_size_g": 100,
    "nutrients": {
      "energy_kcal": 165,
      "protein_g": 31,
      ...
    }
  }
]
```

---

### 5. Planes Semanales

#### GET /weeklyplan/latest/:patient_id

Obtener el plan semanal más reciente de un paciente. **Requiere autenticación.**

**Parámetros:**

- `patient_id` (path): ID del paciente

**Respuesta:**

```json
{
  "_id": "...",
  "patient_id": "...",
  "week_start": "2024-01-01",
  "dailyCalories": 2000,
  "protein": 150,
  "fat": 70,
  "carbs": 250,
  "meals": [
    {
      "day": "monday",
      "type": "desayuno",
      "time": "08:00",
      "foods": [{ "food_id": "...", "grams": 100 }]
    }
  ]
}
```

---

#### GET /weeklyplan/daily/:patient_id

Obtener el plan del día actual para un paciente. **Requiere autenticación.**

**Parámetros:**

- `patient_id` (path): ID del paciente

**Respuesta:** Mismo formato que el anterior pero con las comidas del día actual (basado en zona horaria Tijuana).

---

### 6. Registros de Comidas (Daily Meal Logs)

#### GET /daily-nutrition

Obtener nutrición diaria. **Requiere autenticación.**

**Query params:**

- `patient_id`: ID del paciente
- `date`: Fecha en formato ISO (ej: "2024-01-15")

**Respuesta:**

```json
{
  "date": "2024-01-15T00:00:00.000Z",
  "consumed": {
    "calories": 1800,
    "protein": 120,
    "fat": 60,
    "carbs": 200
  },
  "meals": [...]
}
```

---

#### GET /daily-meal-logs/today/:patient_id

Obtener el registro de comidas de hoy. **Requiere autenticación.**

**Parámetros:**

- `patient_id` (path): ID del paciente

**Respuesta:**

```json
{
  "date": "2024-01-15T00:00:00.000Z",
  "totals": {
    "calories": 1500,
    "protein": 100,
    "fat": 50,
    "carbs": 180
  },
  "meals": [...],
  "notes": "..."
}
```

---

#### GET /daily-meal-logs/all/:patient_id

Obtener todos los registros de comidas del paciente. **Requiere autenticación.**

**Parámetros:**

- `patient_id` (path): ID del paciente

**Respuesta:** Array de registros de comidas ordenados por fecha descendente.

---

#### GET /daily-meal-logs/by-date

Obtener registro de comidas por fecha específica. **Requiere autenticación.**

**Query params:**

- `patient_id`: ID del paciente
- `date`: Fecha en formato ISO

**Respuesta:**

```json
{
  "_id": "...",
  "date": "2024-01-15T00:00:00.000Z",
  "meals": [...],
  "totals": {
    "calories": 1500,
    "protein": 100,
    "fat": 50,
    "carbs": 180
  }
}
```

---

#### POST /daily-meal-logs/add-meal

Añadir una comida al registro diario. **Requiere autenticación.**

**Body:**

```json
{
  "patient_id": "string",
  "meal": {
    "type": "desayuno|comida|cena|snack",
    "time": "08:00",
    "foods": [
      { "food_id": "id_del_alimento", "grams": 100 }
    ]
  },
  "weight": 150 (optional) - Si se especifica, ajusta las porciones
}
```

**Respuesta:**

```json
{
  "message": "Comida anadida al log diario",
  "dailyLog": { ... }
}
```

---

#### POST /daily-meal-logs/add-weekly-meal

Añadir una comida del plan semanal al registro diario. **Requiere autenticación.**

**Body:**

```json
{
  "patient_id": "string",
  "meal": {
    "day": "monday",
    "type": "desayuno",
    "time": "08:00",
    "foods": [{ "food_id": "...", "grams": 100 }]
  }
}
```

---

#### POST /DailyMealLogs/add-custom-meal

Añadir una comida personalizada al registro diario. **Requiere autenticación.**

**Body:**

```json
{
  "patient_id": "string",
  "meal_id": "id_de_patient_meal",
  "type": "desayuno",
  "time": "08:00"
}
```

---

#### POST /dailymeallogs/add-food

Añadir un alimento escaneado (scanner de código de barras) al registro diario. **Requiere autenticación.**

**Body:**

```json
{
  "patient_id": "string",
  "type": "desayuno|comida|cena|snack",
  "time": "08:00",
  "food_data": {
    "food_name": "string",
    "serving_weight_grams": 100,
    "nf_calories": 200,
    "nf_protein": 10,
    "nf_total_carbohydrate": 30,
    "nf_total_fat": 5,
    "nf_dietary_fiber": 3,
    "nf_sugars": 5,
    "category": "general"
  }
}
```

**Respuesta:**

```json
{
  "message": "Alimento añadido al log diario",
  "dailyLog": { ... }
}
```

---

#### DELETE /daily-meal-logs/:logId/meals/:mealId

Eliminar una comida del registro diario. **Requiere autenticación.**

**Parámetros:**

- `logId` (path): ID del registro diario
- `mealId` (path): ID de la comida a eliminar

**Respuesta:**

```json
{
  "message": "Meal deleted successfully.",
  "dailyLog": { ... }
}
```

---

### 7. Comidas Personalizadas (Patient Meals)

#### POST /PatientMeals

Crear una comida personalizada. **Requiere autenticación.**

**Body:**

```json
{
  "patient_id": "string",
  "name": "string",
  "ingredients": [{ "food_id": "id_del_alimento", "amount_g": 100 }],
  "nutrients": {
    "calories": 500,
    "protein": 30,
    "carbs": 40,
    "fat": 20
  },
  "instructions": "string (opcional)"
}
```

**Respuesta:**

```json
{
  "message": "Comida personalizada creada con exito",
  "meal": {
    "_id": "...",
    "patient_id": "...",
    "name": "Mi Ensalada",
    "ingredients": [...],
    "nutrients": {...},
    ...
  }
}
```

---

#### GET /PatientMeals/:patient_id

Obtener todas las comidas personalizadas de un paciente. **Requiere autenticación.**

**Parámetros:**

- `patient_id` (path): ID del paciente

**Respuesta:** Array de comidas personalizadas.

---

#### PUT /PatientMeals/:meal_id

Actualizar una comida personalizada. **Requiere autenticación.**

**Parámetros:**

- `meal_id` (path): ID de la comida

**Body:** Campos a actualizar (name, ingredients)

---

#### DELETE /PatientMeals/:meal_id

Eliminar una comida personalizada. **Requiere autenticación.**

**Parámetros:**

- `meal_id` (path): ID de la comida

---

### 8. Citas

#### GET /appointments/:patient_id

Obtener las citas de un paciente. **Requiere autenticación.**

**Parámetros:**

- `patient_id` (path): ID del paciente

**Respuesta:**

```json
[
  {
    "_id": "...",
    "patient_id": "...",
    "nutritionist_id": "...",
    "date": "2024-01-20T14:00:00.000Z",
    "status": "scheduled",
    "notes": "Primera consulta"
  }
]
```

---

## Resumen de Rutas

| Método | Endpoint                              | Autenticación | Descripción                     |
| ------ | ------------------------------------- | ------------- | ------------------------------- |
| POST   | /login                                | No            | Iniciar sesión                  |
| POST   | /send-reset-code                      | No            | Enviar código de recuperación   |
| PUT    | /patients/change-password             | Sí            | Cambiar contraseña              |
| GET    | /user/:username                       | Sí            | Obtener paciente por username   |
| PUT    | /patient/:id                          | Sí            | Actualizar paciente             |
| GET    | /nutritionist/:id                     | Sí            | Obtener nutricionista           |
| POST   | /search-food                          | Sí            | Buscar alimentos                |
| GET    | /api/food                             | Sí            | Listar alimentos                |
| GET    | /weeklyplan/latest/:patient_id        | Sí            | Plan semanal más reciente       |
| GET    | /weeklyplan/daily/:patient_id         | Sí            | Plan del día actual             |
| GET    | /daily-nutrition                      | Sí            | Nutrición diaria                |
| GET    | /daily-meal-logs/today/:patient_id    | Sí            | Log de hoy                      |
| GET    | /daily-meal-logs/all/:patient_id      | Sí            | Todos los logs                  |
| GET    | /daily-meal-logs/by-date              | Sí            | Log por fecha                   |
| POST   | /daily-meal-logs/add-meal             | Sí            | Añadir comida                   |
| POST   | /daily-meal-logs/add-weekly-meal      | Sí            | Añadir comida del plan          |
| POST   | /DailyMealLogs/add-custom-meal        | Sí            | Añadir comida personalizada     |
| POST   | /dailymeallogs/add-food               | Sí            | Añadir alimento del scanner     |
| DELETE | /daily-meal-logs/:logId/meals/:mealId | Sí            | Eliminar comida                 |
| POST   | /PatientMeals                         | Sí            | Crear comida personalizada      |
| GET    | /PatientMeals/:patient_id             | Sí            | Listar comidas personalizadas   |
| PUT    | /PatientMeals/:meal_id                | Sí            | Actualizar comida personalizada |
| DELETE | /PatientMeals/:meal_id                | Sí            | Eliminar comida personalizada   |
| GET    | /appointments/:patient_id             | Sí            | Listar citas                    |

---

## Notas

- Todas las rutas (excepto `/api/food`) no tienen prefijo `/api` en el backend
- El frontend añade el prefijo `/api` globalmente via Axios
- Todos los timestamps usan la zona horaria de Tijuana (America/Tijuana)
- Los IDs de MongoDB son strings de 24 caracteres hexadecimales
- El token JWT contiene: `{ id, username, email }` con expiración de 24 horas
