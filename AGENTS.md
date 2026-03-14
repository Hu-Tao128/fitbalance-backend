# AGENTS.md - FitBalance Backend

## Project Overview

This is a Node.js + Express + TypeScript backend API for a nutrition app. It uses MongoDB (Mongoose), Luxon for timezone-aware dates (`America/Tijuana`), and is deployed with Docker + Fly.io.

---

## Build, Lint & Test Commands

### Development
```bash
npm run dev          # Start with hot-reload (ts-node-dev)
```

### Build
```bash
npm run build        # Compile TypeScript to dist/
npm run start        # Run compiled code (node dist/index.js)
```

### Testing
- **No test framework is currently configured.** Tests are not set up.
- If adding tests, use Jest or Vitest:
  ```bash
  npm install --save-dev jest @types/jest ts-jest
  npx jest --testPathPattern=filename  # Run single test file
  ```

### Linting
- **No linter is configured.** Consider adding ESLint:
  ```bash
  npm install --save-dev eslint @typescript-eslint/parser @typescript-eslint/eslint-plugin
  npx eslint src/           # Lint project
  npx eslint src/index.ts   # Lint single file
  ```

---

## Code Style Guidelines

### TypeScript Configuration
- `strict: true` is enabled in `tsconfig.json`
- Target: ES2020, Module: CommonJS
- Always enable strict type checking

### Imports
- Use ES6 import syntax
- Single quotes for strings: `import express from 'express'`
- Group external imports first, then blank line, then internal imports
```typescript
import axios from "axios";
import bcrypt from 'bcryptjs';
import cors from 'cors';

import { DateTime } from 'luxon';
```

### Naming Conventions
- **Variables/functions**: camelCase (`nowInTijuana`, `getFatSecretToken`)
- **Interfaces/Types**: PascalCase (`IPatient`, `IWeeklyMeal`)
- **Models (Mongoose)**: PascalCase (`Patient`, `Food`, `WeeklyPlan`)
- **Constants**: UPPER_SNAKE_CASE (`SALT_ROUNDS`, `PORT`)
- **File names**: camelCase (or index.ts for monolithic structure)

### Type Definitions
- Always use explicit types for function parameters and return types
- Use `any` sparingly - prefer explicit interfaces
```typescript
// Good
function getEnv(name: string): string { ... }

// Avoid
function getEnv(name) { ... }
```

### Interfaces (Mongoose)
- Prefix with `I` for interfaces: `IPatient`, `IFood`
- Use `extends Document` for Mongoose document interfaces
- Define subdocument interfaces separately when complex

### Error Handling
- Always wrap async route handlers in try/catch
- Return appropriate HTTP status codes (400, 401, 404, 500)
- Log errors with `console.error` including context
```typescript
try {
  const result = await someOperation();
  res.json(result);
} catch (error: any) {
  console.error('❌ Error in /endpoint:', error);
  res.status(500).json({ error: 'Descriptive error message' });
}
```

### Environment Variables
- Use `getEnv()` helper for required variables
- Never hardcode secrets in source code
- Validate required env vars at startup

### Mongoose Schemas
- Define schemas with explicit field types and validation
- Use enums for constrained string fields
- Always set `collection` name explicitly
- Use `.lean()` for read-only queries

### API Routes
- Validate all required request parameters
- Return 400 for missing/invalid input
- Return 404 for not found, 401 for unauthorized
- Keep route handlers focused (delegate logic to functions)

### Date/Time Handling
- Use Luxon with `America/Tijuana` timezone
- Use helper functions: `nowInTijuana()`, `todayStartInTijuana()`, `todayEndInTijuana()`

### Database Queries
- Always validate ObjectId params: `mongoose.Types.ObjectId.isValid(id)`
- Use `new Types.ObjectId(id)` for proper casting
- Use projections to exclude sensitive fields (`select('-password')`)

### Security
- Never log sensitive data (passwords, tokens)
- Use `select: false` for password fields in schemas
- Validate all user input

---

## Project Structure (Current)

```
src/
└── index.ts        # All models and endpoints in one file
dist/               # Compiled output
```

---

## Environment Variables Required

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

---

## Key Implementation Notes

- All logic currently in `src/index.ts` (monolithic)
- Multiple Mongoose models in single file
- Routes mix naming conventions (kebab-case and PascalCase) - match existing paths exactly for frontend compatibility
- Timezone is hardcoded to `America/Tijuana` throughout

---

## Recommendations for Future Development

1. Split into modular structure (routes/, controllers/, services/, models/)
2. Add request validation (Zod or Joi)
3. Add ESLint + Prettier
4. Add Jest/Vitest tests
5. Standardize route naming (kebab-case)
6. Add API documentation (Swagger/OpenAPI)
