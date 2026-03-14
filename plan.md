# Plan de Migración: Arquitectura de Capas

## Estado Actual
- Todo en `src/index.ts` (~1600 líneas)
- Múltiples modelos Mongoose
- ~30+ endpoints Express
- Sin tests, sin linter

---

## Objetivo
Migrar a arquitectura de capas manteniendo funcionalidad actual.

---

## Fases del Plan

### Fase 1: Preparación (Día 1)
- [x] 1.1 Crear estructura de carpetas base
- [x] 1.2 Configurar TypeScript para nueva estructura (`tsconfig.json` update)
- [x] 1.3 Instalar dependencias necesarias (si aplica)
- [x] 1.4 Hacer backup del archivo actual (`cp src/index.ts src/index.ts.backup`)

### Fase 2: Extraer Modelos (Día 1-2)
- [x] 2.1 Crear `src/models/Patient.ts`
- [x] 2.2 Crear `src/models/Food.ts`
- [x] 2.3 Crear `src/models/WeeklyPlan.ts`
- [x] 2.4 Crear `src/models/DailyMealLog.ts`
- [x] 2.5 Crear `src/models/PatientMeal.ts`
- [x] 2.6 Crear `src/models/Appointment.ts`
- [x] 2.7 Crear `src/models/Nutritionist.ts`
- [x] 2.8 Crear `src/models/PasswordResetToken.ts`
- [x] 2.9 Crear `src/models/index.ts` (exports)
- [x] 2.10 Verificar que compila

### Fase 3: Extraer Tipos (Día 2)
- [x] 3.1 Crear `src/types/index.ts` para interfaces compartilhadas
- [x] 3.2 Mover interfaces como `IFood`, `IWeeklyMeal`, etc.
- [x] 3.3 Definir tipos de request/response para endpoints

### Fase 4: Extraer Servicios (Día 2-3)
- [x] 4.1 Crear `src/services/dateService.ts` (helpers de Luxon)
- [x] 4.2 Crear `src/services/emailService.ts` (Nodemailer)
- [x] 4.3 Crear `src/services/fatSecretService.ts`
- [x] 4.4 Crear `src/services/nutritionixService.ts`
- [x] 4.5 Crear `src/services/nutritionCalculator.ts` (calculateDailyTotals)
- [x] 4.6 Crear `src/services/index.ts`

### Fase 5: Extraer Controladores (Día 3-4)
- [x] 5.1 Crear `src/controllers/authController.ts` (login, reset-password)
- [x] 5.2 Crear `src/controllers/patientController.ts`
- [x] 5.3 Crear `src/controllers/foodController.ts`
- [x] 5.4 Crear `src/controllers/weeklyPlanController.ts`
- [x] 5.5 Crear `src/controllers/dailyMealLogController.ts`
- [x] 5.6 Crear `src/controllers/patientMealController.ts`
- [x] 5.7 Crear `src/controllers/appointmentController.ts`
- [x] 5.8 Crear `src/controllers/nutritionistController.ts`
- [x] 5.9 Crear `src/controllers/index.ts`

### Fase 6: Extraer Rutas (Día 4-5)
- [x] 6.1 Crear `src/routes/authRoutes.ts`
- [x] 6.2 Crear `src/routes/patientRoutes.ts`
- [x] 6.3 Crear `src/routes/foodRoutes.ts`
- [x] 6.4 Crear `src/routes/weeklyPlanRoutes.ts`
- [x] 6.5 Crear `src/routes/dailyMealLogRoutes.ts`
- [x] 6.6 Crear `src/routes/patientMealRoutes.ts`
- [x] 6.7 Crear `src/routes/appointmentRoutes.ts`
- [x] 6.8 Crear `src/routes/nutritionistRoutes.ts`
- [x] 6.9 Crear `src/routes/index.ts` (aggregates all routes)

### Fase 7: Refactorizar Entry Point (Día 5)
- [x] 7.1 Crear `src/app.ts` (Express app config)
- [x] 7.2 Crear `src/index.ts` (server bootstrap)
- [x] 7.3 Mover configuración de Express (cors, json)
- [x] 7.4 Mover conexión a MongoDB
- [x] 7.5 Verificar que endpoint `/health` responde

### Fase 8: Limpieza y Tests (Día 6)
- [x] 8.1 Eliminar archivo `src/index.ts.backup`
- [x] 8.2 Eliminar código duplicado
- [x] 8.3 Agregar Jest + configuración inicial
- [x] 8.4 Escribir tests básicos para modelos
- [x] 8.5 Agregar ESLint + Prettier
- [x] 8.6 Validar que `npm run build` funciona

### Fase 9: Documentación (Día 7)
- [x] 9.1 Actualizar README.md
- [x] 9.2 Crear docs de contribución
- [x] 9.3 Documentar estructura de carpetas

---

## Estructura Final

```
src/
├── index.ts              # Entry point (server bootstrap)
├── app.ts                # Express app configuration
├── config/
│   └── env.ts            # Environment variables
├── models/
│   ├── Patient.ts
│   ├── Food.ts
│   ├── WeeklyPlan.ts
│   ├── DailyMealLog.ts
│   ├── PatientMeal.ts
│   ├── Appointment.ts
│   ├── Nutritionist.ts
│   ├── PasswordResetToken.ts
│   └── index.ts
├── types/
│   └── index.ts
├── services/
│   ├── dateService.ts
│   ├── emailService.ts
│   ├── fatSecretService.ts
│   ├── nutritionixService.ts
│   ├── nutritionCalculator.ts
│   └── index.ts
├── controllers/
│   ├── authController.ts
│   ├── patientController.ts
│   ├── foodController.ts
│   ├── weeklyPlanController.ts
│   ├── dailyMealLogController.ts
│   ├── patientMealController.ts
│   ├── appointmentController.ts
│   ├── nutritionistController.ts
│   └── index.ts
└── routes/
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

---

## Notas Importantes

1. **Migración incremental**: Cada fase debe compilar y funcionar
2. **Compatibilidad**: Mantener rutas exactas (kebab-case vs PascalCase) para no romper el frontend
3. **Sin features nuevos**: Solo refactorizar, no agregar funcionalidad
4. **Tests**: Agregar después de tener estructura estable

---

## Tiempo Estimado
- **Total**: 5-7 días (trabajando 2-4 hrs/día)
- **Crítico**: Fases 1-3 (fundamentos)
- **Riesgo**: Fase 6 (rutas) - requiere atención a compatibilidad
