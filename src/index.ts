import axios from "axios";
import bcrypt from 'bcrypt';
import cors from 'cors';
import dotenv from 'dotenv';
import express, { Request, Response } from 'express';
<<<<<<< HEAD
import mongoose, { Document, Schema, Types } from 'mongoose';
=======
import mongoose from 'mongoose';
>>>>>>> parent of 6b93fbc (nuevo back)

dotenv.config();

const app = express();
app.use(cors());
app.use(express.json());

// 👉 Utilidad para leer variables de entorno obligatorias
function getEnv(name: string): string {
  const value = process.env[name];
  if (!value) throw new Error(`❌ La variable ${name} no está definida en process.env`);
  return value;
}

const PORT = process.env.PORT || 3000;

// 🌱 Variables de entorno necesarias
const MONGODB_URI = getEnv('MONGODB_URI');
const FATSECRET_CONSUMER_KEY = getEnv('FATSECRET_CONSUMER_KEY');
const FATSECRET_CONSUMER_SECRET = getEnv('FATSECRET_CONSUMER_SECRET');
const NUTRITIONIX_APP_ID = getEnv('NUTRITIONIX_APP_ID');
const NUTRITIONIX_APP_KEY = getEnv('NUTRITIONIX_APP_KEY');

// 📦 Modelos de Mongoose
interface IPatient {
  nombre: string;
  correo: string;
  email: string;
  usuario: string;
  password: string;
  edad?: number;
  sexo?: string;
  altura_cm?: number;
  peso_kg?: number;
  objetivo?: string;
  ultima_consulta?: string;
}

const Patient = mongoose.model<IPatient>(
  'Patient',
  new mongoose.Schema({
    nombre: { type: String, required: true },
    correo: { type: String, required: true },
    usuario: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    edad: { type: Number },
    sexo: { type: String },
    altura_cm: { type: Number },
    peso_kg: { type: Number },
    objetivo: { type: String },
    ultima_consulta: { type: String }
  }, { collection: 'Patients' })
);

interface IFood {
  name: string;
  portion_size_g: number;
  category: string;
  nutrients: {
    energy_kj: number;
    energy_kcal: number;
    fat_g: number;
    saturated_fat_g: number;
    monounsaturated_fat_g: number;
    polyunsaturated_fat_g: number;
    carbohydrates_g: number;
    sugar_g: number;
    fiber_g: number;
    protein_g: number;
    salt_g: number;
    cholesterol_mg: number;
    potassium_mg: number;
  };
  percent_RI: any;
}

const Food = mongoose.model<IFood>(
  'Food',
  new mongoose.Schema({}, { strict: false, collection: 'Food' })
);

<<<<<<< HEAD
// 🍽️ NUEVO: Modelo para PatientMeal
interface IPatientMealIngredient {
  food_id: string;
  amount_g: number;
}

interface IPatientMeal extends Document {
  patient_id: string;
  name: string;
  ingredients: IPatientMealIngredient[];
  nutrients: {
    energy_kcal: number;
    protein_g: number;
    carbohydrates_g: number;
    fat_g: number;
    fiber_g: number;
    sugar_g: number;
  };
  instructions?: string;
  created_at: Date;
  updated_at: Date;
}

const PatientMealSchema = new Schema<IPatientMeal>({
  patient_id: { type: String, required: true },
  name: { type: String, required: true },
  ingredients: [{
    food_id: { type: String, required: true },
    amount_g: { type: Number, required: true, min: 1 }
  }],
  nutrients: {
    energy_kcal: { type: Number, required: true, min: 0 },
    protein_g: { type: Number, required: true, min: 0 },
    carbohydrates_g: { type: Number, required: true, min: 0 },
    fat_g: { type: Number, required: true, min: 0 },
    fiber_g: { type: Number, required: true, min: 0 },
    sugar_g: { type: Number, required: true, min: 0 }
  },
  instructions: { type: String, default: '' },
  created_at: { type: Date, default: Date.now },
  updated_at: { type: Date, default: Date.now }
}, {
  collection: 'PatientMeals',
  timestamps: true
});

const PatientMeal = mongoose.model<IPatientMeal>('PatientMeal', PatientMealSchema);

// 📊 NUEVO: Modelo para Daily Meal Log
interface IDailyMealLogFood {
  food_id: string;
  grams: number;
}

interface IDailyMealLogMeal {
  name: string;
  time: string;
  day: string;
  type: 'breakfast' | 'lunch' | 'dinner' | 'snack';
  foods: IDailyMealLogFood[];
}

interface IDailyMealLog extends Document {
  patient_id: string;
  date: Date;
  nutrients: {
    energy_kcal: number;
    protein_g: number;
    carbohydrates_g: number;
    fat_g: number;
    fiber_g: number;
    sugar_g: number;
  };
  meal: IDailyMealLogMeal;
  created_at: Date;
}

const DailyMealLogSchema = new Schema<IDailyMealLog>({
  patient_id: { type: String, required: true },
  date: { type: Date, default: Date.now },
  nutrients: {
    energy_kcal: { type: Number, required: true, min: 0 },
    protein_g: { type: Number, required: true, min: 0 },
    carbohydrates_g: { type: Number, required: true, min: 0 },
    fat_g: { type: Number, required: true, min: 0 },
    fiber_g: { type: Number, required: true, min: 0 },
    sugar_g: { type: Number, required: true, min: 0 }
  },
  meal: {
    name: { type: String, required: true },
    time: { type: String, required: true },
    day: { type: String, required: true },
    type: { type: String, enum: ['breakfast', 'lunch', 'dinner', 'snack'], required: true },
    foods: [{
      food_id: { type: String, required: true },
      grams: { type: Number, required: true, min: 1 }
    }]
  },
  created_at: { type: Date, default: Date.now }
}, {
  collection: 'DailyMealLogs',
  timestamps: true
});

const DailyMealLog = mongoose.model<IDailyMealLog>('DailyMealLog', DailyMealLogSchema);

interface IWeeklyPlanFood {
  food_id: string;
  grams: number;
}

const FoodSchema = new Schema<IWeeklyPlanFood>({
  food_id: { type: String, required: true },
  grams: { type: Number, required: true, min: 1 },
}, { _id: false });

interface IWeeklyMeal {
  day: 'monday' | 'tuesday' | 'wednesday' | 'thursday' | 'friday' | 'saturday' | 'sunday';
  type: 'breakfast' | 'lunch' | 'dinner' | 'snack';
  time: string;
  foods: IWeeklyPlanFood[];
}

const MealSchema = new Schema<IWeeklyMeal>({
  day: {
    type: String,
    enum: ['monday', 'tuesday', 'wednesday', 'thursday', 'friday', 'saturday', 'sunday'],
    required: true,
  },
  type: {
    type: String,
    enum: ['breakfast', 'lunch', 'dinner', 'snack'],
    required: true,
  },
  time: { type: String, required: true },
  foods: { type: [FoodSchema], required: true },
}, { _id: false });

export interface IWeeklyPlan extends Document {
  patient_id: Types.ObjectId;
  week_start: Date;
  dailyCalories: number;
  protein: number;
  fat: number;
  carbs: number;
  meals: IWeeklyMeal[];
}

const WeeklyPlanSchema = new Schema<IWeeklyPlan>({
  patient_id: { type: Schema.Types.ObjectId, required: true, ref: 'Patient' },
  week_start: { type: Date, required: true },
  dailyCalories: { type: Number, required: true },
  protein: { type: Number, required: true },
  fat: { type: Number, required: true },
  carbs: { type: Number, required: true },
  meals: { type: [MealSchema], required: true },
}, {
  collection: 'WeeklyPlan',
  timestamps: true
});

const WeeklyPlan = mongoose.model<IWeeklyPlan>('WeeklyPlan', WeeklyPlanSchema);

=======
>>>>>>> parent of 6b93fbc (nuevo back)
// 🔌 Conexión a MongoDB
mongoose.connect(MONGODB_URI)
  .then(() => console.log('✅ Conectado a MongoDB Atlas'))
  .catch((err) => {
    console.error('❌ Error al conectar a MongoDB:', err);
    process.exit(1);
  });

// 🧠 Token de FatSecret (con cache)
let fatSecretAccessToken: string | null = null;
let fatSecretTokenExpiry = 0;

async function getFatSecretToken(): Promise<string> {
  const clientId = FATSECRET_CONSUMER_KEY;
  const clientSecret = FATSECRET_CONSUMER_SECRET;

  const credentials = Buffer.from(`${clientId}:${clientSecret}`).toString('base64');

  const response = await axios.post(
    'https://oauth.fatsecret.com/connect/token',
    new URLSearchParams({
      grant_type: 'client_credentials',
      scope: 'basic'
    }),
    {
      headers: {
        'Authorization': `Basic ${credentials}`,
        'Content-Type': 'application/x-www-form-urlencoded'
      }
    }
  );

  const token = response.data.access_token;

  if (!token) throw new Error('❌ No se pudo obtener el token de FatSecret');

  return token;
}

// 🔎 Función para buscar en FatSecret
async function searchFatSecretByText(query: string) {
  const accessToken = await getFatSecretToken();

  const response = await axios.post(
    'https://platform.fatsecret.com/rest/server.api',
    new URLSearchParams({
      method: 'foods.search',
      search_expression: query,
      format: 'json',
      max_results: '10'
    }),
    {
      headers: {
        'Authorization': `Bearer ${accessToken}`,
        'Content-Type': 'application/x-www-form-urlencoded'
      }
    }
  );

  return response.data;
}

// 🧠 Ruta combinada de búsqueda nutricional
app.post('/search-food', async (req: Request, res: Response) => {
  const { query } = req.body;

  if (!query) {
    return res.status(400).json({ error: 'Falta el parámetro "query"' });
  }

  try {
    const nutritionixResponse = await axios.post(
      'https://trackapi.nutritionix.com/v2/natural/nutrients',
      { query },
      {
        headers: {
          'x-app-id': NUTRITIONIX_APP_ID,
          'x-app-key': NUTRITIONIX_APP_KEY,
          'Content-Type': 'application/json'
        }
      }
    );

    const items = nutritionixResponse.data.foods;
    if (items && items.length > 0) {
      return res.json({
        source: 'nutritionix',
        results: items
      });
    }

    const fatSecretData = await searchFatSecretByText(query);
    const foods = fatSecretData?.foods?.food;

    if (foods && foods.length > 0) {
      return res.json({
        source: 'fatsecret',
        results: foods
      });
    }

    return res.status(404).json({ message: 'No se encontraron alimentos con ese nombre.' });

  } catch (error: any) {
    console.error('❌ Error en /search-food:', error.message);
    return res.status(500).json({ error: 'Error en la búsqueda de alimentos' });
  }
});

// 🧾 Rutas de usuarios
app.get('/usuarios', async (_req, res) => {
  try {
<<<<<<< HEAD
    const patient = await Patient.findOne({ username });

    if (!patient) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }

    const isMatch = await bcrypt.compare(password, patient.password);
    if (!isMatch) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }

    // Eliminar el campo password antes de enviar
    const { password: _, ...safePatient } = patient.toObject();

    res.json({
      message: 'Login successful',
      ...safePatient
    });

  } catch (err) {
    console.error('❌ Error en /login:', err);
    res.status(500).json({ error: 'Server error' });
=======
    const usuarios = await Patient.find();
    res.json(usuarios);
  } catch (err) {
    res.status(500).json({ error: 'Error al obtener usuarios' });
>>>>>>> parent of 6b93fbc (nuevo back)
  }
});

app.post('/usuarios', async (req, res) => {
  try {
    const nuevoUsuario = new Patient(req.body);
    await nuevoUsuario.save();
    res.status(201).json(nuevoUsuario);
  } catch (err) {
    res.status(500).json({ error: 'Error al guardar usuario' });
  }
});

app.post('/login', async (req, res) => {
  const { usuario, password } = req.body;

  if (!usuario || !password) {
    return res.status(400).json({ mensaje: 'Faltan campos: usuario y/o contraseña' });
  }

  try {
    const paciente = await Patient.findOne({ usuario, password }).select('-password');

    if (!paciente) {
      return res.status(401).json({ mensaje: 'Credenciales incorrectas' });
    }

    res.json({
      mensaje: 'Inicio de sesión exitoso',
      id: paciente._id,
      usuario: paciente.usuario,
      nombre: paciente.nombre,
      correo: paciente.correo || paciente.email
    });
  } catch (err) {
    res.status(500).json({ error: 'Error del servidor' });
  }
});

app.get('/user/:usuario', async (req, res) => {
  const { usuario } = req.params;

  try {
    const paciente = await Patient.findOne({ usuario }).select('-password');

    if (!paciente) {
      return res.status(404).json({ mensaje: 'Usuario no encontrado' });
    }

    res.json(paciente);
  } catch (err) {
    res.status(500).json({ error: 'Error al obtener los datos del usuario' });
  }
});

// 🍽 Ruta para obtener alimentos guardados
app.get('/api/food', async (_req, res) => {
  try {
    const foods = await Food.find();
    res.json(foods);
  } catch (err) {
    console.error('❌ Error al obtener alimentos:', err);
    res.status(500).json({ error: 'Error al obtener alimentos' });
  }
});

<<<<<<< HEAD
// 🍽️ NUEVO: Endpoints para PatientMeals

// Crear una nueva comida personalizada
app.post('/patient_meals', async (req: Request, res: Response) => {
  try {
    const {
      patient_id,
      name,
      ingredients,
      nutrients,
      instructions
    } = req.body;

    console.log('📝 Creando nueva comida:', { patient_id, name, ingredients: ingredients?.length });

    // Validaciones básicas
    if (!patient_id || !name || !ingredients || !nutrients) {
      return res.status(400).json({
        error: 'Faltan campos obligatorios: patient_id, name, ingredients, nutrients'
      });
    }

    if (!Array.isArray(ingredients) || ingredients.length === 0) {
      return res.status(400).json({
        error: 'ingredients debe ser un array con al menos un elemento'
      });
    }

    // Validar que todos los ingredientes tengan food_id y amount_g válidos
    for (const ingredient of ingredients) {
      if (!ingredient.food_id || !ingredient.amount_g || ingredient.amount_g <= 0) {
        return res.status(400).json({
          error: 'Cada ingrediente debe tener food_id y amount_g válidos'
        });
      }
    }

    // Validar que los nutrientes sean números válidos
    const requiredNutrients = ['energy_kcal', 'protein_g', 'carbohydrates_g', 'fat_g', 'fiber_g', 'sugar_g'];
    for (const nutrient of requiredNutrients) {
      if (typeof nutrients[nutrient] !== 'number' || nutrients[nutrient] < 0) {
        return res.status(400).json({
          error: `El nutriente ${nutrient} debe ser un número válido mayor o igual a 0`
        });
      }
    }

    // Crear la nueva comida
    const newMeal = new PatientMeal({
      patient_id,
      name: name.trim(),
      ingredients,
      nutrients,
      instructions: instructions?.trim() || '',
      created_at: new Date(),
      updated_at: new Date()
    });

    const savedMeal = await newMeal.save();

    console.log('✅ Comida creada exitosamente:', savedMeal._id);

    res.status(201).json({
      message: 'Comida creada exitosamente',
      meal: savedMeal
    });

  } catch (error: any) {
    console.error('❌ Error al crear comida:', error);

    if (error.name === 'ValidationError') {
      return res.status(400).json({
        error: 'Error de validación',
        details: error.message
      });
    }

    res.status(500).json({
      error: 'Error interno del servidor al crear la comida'
    });
  }
});

// Obtener todas las comidas de un paciente
app.get('/patient_meals/:patient_id', async (req: Request, res: Response) => {
  try {
    const { patient_id } = req.params;

    if (!patient_id) {
      return res.status(400).json({ error: 'patient_id es requerido' });
    }

    const meals = await PatientMeal.find({ patient_id })
      .sort({ created_at: -1 })
      .lean();

    res.json(meals);

  } catch (error: any) {
    console.error('❌ Error al obtener comidas del paciente:', error);
    res.status(500).json({ error: 'Error al obtener las comidas del paciente' });
  }
});

// Obtener una comida específica
app.get('/patient_meals/meal/:meal_id', async (req: Request, res: Response) => {
  try {
    const { meal_id } = req.params;

    if (!mongoose.Types.ObjectId.isValid(meal_id)) {
      return res.status(400).json({ error: 'ID de comida no válido' });
    }

    const meal = await PatientMeal.findById(meal_id).lean();

    if (!meal) {
      return res.status(404).json({ error: 'Comida no encontrada' });
    }

    res.json(meal);

  } catch (error: any) {
    console.error('❌ Error al obtener comida:', error);
    res.status(500).json({ error: 'Error al obtener la comida' });
  }
});

// Actualizar una comida
app.put('/patient_meals/:meal_id', async (req: Request, res: Response) => {
  try {
    const { meal_id } = req.params;
    const updateData = req.body;

    if (!mongoose.Types.ObjectId.isValid(meal_id)) {
      return res.status(400).json({ error: 'ID de comida no válido' });
    }

    updateData.updated_at = new Date();

    const updatedMeal = await PatientMeal.findByIdAndUpdate(
      meal_id,
      updateData,
      { new: true, runValidators: true }
    );

    if (!updatedMeal) {
      return res.status(404).json({ error: 'Comida no encontrada' });
    }

    res.json({
      message: 'Comida actualizada exitosamente',
      meal: updatedMeal
    });

  } catch (error: any) {
    console.error('❌ Error al actualizar comida:', error);
    res.status(500).json({ error: 'Error al actualizar la comida' });
  }
});

// Eliminar una comida
app.delete('/patient_meals/:meal_id', async (req: Request, res: Response) => {
  try {
    const { meal_id } = req.params;

    if (!mongoose.Types.ObjectId.isValid(meal_id)) {
      return res.status(400).json({ error: 'ID de comida no válido' });
    }

    const deletedMeal = await PatientMeal.findByIdAndDelete(meal_id);

    if (!deletedMeal) {
      return res.status(404).json({ error: 'Comida no encontrada' });
    }

    res.json({
      message: 'Comida eliminada exitosamente',
      meal: deletedMeal
    });

  } catch (error: any) {
    console.error('❌ Error al eliminar comida:', error);
    res.status(500).json({ error: 'Error al eliminar la comida' });
  }
});

// 📊 NUEVO: Endpoints para Daily Meal Logs

// Registrar una comida en el log diario
app.post('/daily-meal-logs/register-meal', async (req: Request, res: Response) => {
  try {
    const { patient_id, nutrients, meal } = req.body;

    console.log('📊 Registrando comida en log diario:', { patient_id, meal: meal?.name });

    // Validaciones básicas
    if (!patient_id || !nutrients || !meal) {
      return res.status(400).json({
        error: 'Faltan campos obligatorios: patient_id, nutrients, meal'
      });
    }

    // Crear el registro del log diario
    const newLog = new DailyMealLog({
      patient_id,
      date: new Date(),
      nutrients,
      meal,
      created_at: new Date()
    });

    const savedLog = await newLog.save();

    console.log('✅ Comida registrada en log diario:', savedLog._id);

    res.status(201).json({
      message: 'Comida registrada en el log diario exitosamente',
      log: savedLog
    });

  } catch (error: any) {
    console.error('❌ Error al registrar en log diario:', error);

    if (error.name === 'ValidationError') {
      return res.status(400).json({
        error: 'Error de validación',
        details: error.message
      });
    }

    res.status(500).json({
      error: 'Error interno del servidor al registrar en el log diario'
    });
  }
});

// Obtener el log diario de un paciente
app.get('/daily-meal-logs/:patient_id', async (req: Request, res: Response) => {
  try {
    const { patient_id } = req.params;
    const { date } = req.query;

    if (!patient_id) {
      return res.status(400).json({ error: 'patient_id es requerido' });
    }

    let query: any = { patient_id };

    // Si se especifica una fecha, filtrar por esa fecha
    if (date) {
      const targetDate = new Date(date as string);
      const startOfDay = new Date(targetDate.setHours(0, 0, 0, 0));
      const endOfDay = new Date(targetDate.setHours(23, 59, 59, 999));

      query.date = {
        $gte: startOfDay,
        $lte: endOfDay
      };
    }

    const logs = await DailyMealLog.find(query)
      .sort({ created_at: -1 })
      .lean();

    res.json(logs);

  } catch (error: any) {
    console.error('❌ Error al obtener logs diarios:', error);
    res.status(500).json({ error: 'Error al obtener los logs diarios' });
  }
});

// Obtener resumen nutricional del día
app.get('/daily-meal-logs/summary/:patient_id', async (req: Request, res: Response) => {
  try {
    const { patient_id } = req.params;
    const { date } = req.query;

    if (!patient_id) {
      return res.status(400).json({ error: 'patient_id es requerido' });
    }

    const targetDate = date ? new Date(date as string) : new Date();
    const startOfDay = new Date(targetDate.setHours(0, 0, 0, 0));
    const endOfDay = new Date(targetDate.setHours(23, 59, 59, 999));

    const logs = await DailyMealLog.find({
      patient_id,
      date: {
        $gte: startOfDay,
        $lte: endOfDay
      }
    }).lean();

    // Calcular totales del día
    const summary = logs.reduce((total, log) => {
      total.energy_kcal += log.nutrients.energy_kcal || 0;
      total.protein_g += log.nutrients.protein_g || 0;
      total.carbohydrates_g += log.nutrients.carbohydrates_g || 0;
      total.fat_g += log.nutrients.fat_g || 0;
      total.fiber_g += log.nutrients.fiber_g || 0;
      total.sugar_g += log.nutrients.sugar_g || 0;
      return total;
    }, {
      energy_kcal: 0,
      protein_g: 0,
      carbohydrates_g: 0,
      fat_g: 0,
      fiber_g: 0,
      sugar_g: 0
    });

    res.json({
      date: targetDate.toISOString().split('T')[0],
      total_meals: logs.length,
      summary,
      meals: logs
    });

  } catch (error: any) {
    console.error('❌ Error al obtener resumen diario:', error);
    res.status(500).json({ error: 'Error al obtener el resumen diario' });
  }
});

app.get('/weeklyplan', async (_req: Request, res: Response) => {
  try {
    const weeklyPlans = await mongoose.model('WeeklyPlan').find().sort({ week_start: -1 }).lean();
    return res.json(weeklyPlans);
  } catch (error) {
    console.error('❌ Error al obtener los WeeklyPlan:', error);
    return res.status(500).json({ error: 'Error al obtener los planes semanales.' });
  }
});

app.get('/weeklyplan/latest/:patient_id', async (req: Request, res: Response) => {
  const { patient_id } = req.params;

  if (!mongoose.Types.ObjectId.isValid(patient_id)) {
    return res.status(400).json({ error: 'ID de paciente no válido' });
  }

  try {
    const latestPlan = await WeeklyPlan.findOne({
      patient_id: JSON.parse(patient_id),
    })
      .sort({ week_start: -1 })
      .lean();

    if (!latestPlan) {
      return res.status(404).json({ message: 'No se encontró ningún plan semanal.' });
    }

    return res.json(latestPlan);

  } catch (error) {
    console.error('❌ Error en /weeklyplan/latest:', error);
    return res.status(500).json({ error: 'Error al obtener el plan semanal más reciente' });
  }
});

// 📅 Obtener comidas del día actual para un paciente
app.get('/weeklyplan/daily/:patient_id', async (req: Request, res: Response) => {
  const { patient_id } = req.params;

  if (!mongoose.Types.ObjectId.isValid(patient_id)) {
    return res.status(400).json({ error: 'ID de paciente no válido' });
  }

  const today = new Date().toLocaleDateString('en-US', { weekday: 'long' }).toLowerCase();

  try {
    const latestPlan = await WeeklyPlan.findOne({
      patient_id: new mongoose.Types.ObjectId(patient_id)
    }).sort({ week_start: -1 }).lean();

    if (!latestPlan) {
      return res.status(404).json({ message: 'No se encontró ningún plan semanal.' });
    }

    const todayMeals = latestPlan.meals.filter(meal => meal.day === today);

    return res.json({
      dailyCalories: latestPlan.dailyCalories,
      protein: latestPlan.protein,
      fat: latestPlan.fat,
      carbs: latestPlan.carbs,
      meals: todayMeals
    });
  } catch (error) {
    console.error('❌ Error en /weeklyplan/daily:', error);
    return res.status(500).json({ error: 'Error al obtener las comidas del día.' });
  }
});

=======
>>>>>>> parent of 6b93fbc (nuevo back)
// 🚀 Arranque del servidor
app.listen(PORT, () => {
  console.log(`🚀 Servidor corriendo en http://localhost:${PORT}`);
});