import axios from "axios";
import cors from 'cors';
import dotenv from 'dotenv';
import express, { Request, Response } from 'express';
import mongoose, { Document, Schema, Types } from 'mongoose';
import bcrypt from 'bcryptjs';

const SALT_ROUNDS = 10;

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
  _id: string;
  username: string;
  password: string;
  name: string;
  email: string;
  phone?: string;
  age?: number;
  gender?: string;
  height_cm?: number;
  weight_kg?: number;
  objective?: string;
  allergies?: string[];
  dietary_restrictions?: string[];
  registration_date?: Date;
  notes?: string;
  last_consultation?: Date | null;
  nutritionist_id?: string;
  isActive?: boolean;
  portion_size_g: number;
  category: string;
  nutrients: Record<string, number>;
}

const Patient = mongoose.model<IPatient>(
  'Patient',
  new mongoose.Schema({
    _id: { type: String, required: true },
    username: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    name: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    phone: { type: String },
    age: { type: Number },
    gender: { type: String, enum: ['male', 'female', 'other'] },
    height_cm: { type: Number },
    weight_kg: { type: Number },
    objective: { type: String },
    allergies: { type: [String], default: [] },
    dietary_restrictions: { type: [String], default: [] },
    registration_date: { type: Date, default: Date.now },
    notes: { type: String, default: '' },
    last_consultation: { type: Date, default: null },
    nutritionist_id: { type: String },
    isActive: { type: Boolean, default: true }
  }, { collection: 'Patients' })
);

interface IFood {
  name: string;
  portion_size_g: number;
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

app.post('/login', async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ message: 'Missing fields: username and/or password' });
  }

  try {
    const patient = await Patient.findOne({ username }).select('+password');
    
    if (!patient) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }

    const isMatch = await bcrypt.compare(password, patient.password);
    
    if (!isMatch) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }

    const { password: _, ...patientData } = patient.toObject();
    
    res.json({
      message: 'Login successful',
      patient: patientData
    });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

app.get('/user/:username', async (req, res) => {
  const { username } = req.params;

  try {
    const patient = await Patient.findOne({ username }).select('-password');

    if (!patient) {
      return res.status(404).json({ message: 'User not found' });
    }

    res.json(patient);
  } catch (err) {
    res.status(500).json({ error: 'Error fetching user data' });
  }
});

// 🍽 Ruta para obtener alimentos guardados
app.get('/api/food', async (_req, res) => {
  try {
    const foods = await Food.find();
    res.json(foods);
  } catch (err) {
    res.status(500).json({ error: 'Error al obtener alimentos' });
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

// COMIDAS PACIENTES --------------------------------------------------------

interface IPatientMealIngredient { food_id: Types.ObjectId; amount_g: number; }
interface IPatientMeal extends Document {
  patient_id: Types.ObjectId;
  name: string;
  ingredients: IPatientMealIngredient[];
  nutrients: Record<string, number>;
  instructions?: string;
  created_at: Date;
  updated_at: Date;
}


const Food = mongoose.model<IFood>(
  'Food',
  new mongoose.Schema({}, { strict: false, collection: 'Food' })
);


const PatientMealSchema = new Schema<IPatientMeal>({
  patient_id: { type: Schema.Types.ObjectId, required: true, ref: 'Patient' },
  name: { type: String, required: true },
  ingredients: [{
    food_id: { type: Schema.Types.ObjectId, required: true, ref: 'Food' },
    amount_g: { type: Number, required: true, min: 1 }
  }],
  nutrients: {
    energy_kcal: { type: Number, required: true, min: 0 },
    protein_g: { type: Number, required: true, min: 0 },
    carbohydrates_g: { type: Number, required: true, min: 0 },
    fat_g: { type: Number, required: true, min: 0 },
    fiber_g: { type: Number, required: true, min: 0 },
    sugar_g: { type: Number, required: true, min: 0 },
  },
  instructions: { type: String, default: '' },
  created_at: { type: Date, default: Date.now },
  updated_at: { type: Date, default: Date.now },
}, { collection: 'PatientMeals', timestamps: true });

const PatientMeal = mongoose.model<IPatientMeal>('PatientMeal', PatientMealSchema);

// ------------ Ruta alimentos (sin cambios) ------------
app.get('/api/food', async (_req, res) => {
  try { res.json(await Food.find()); }
  catch (err) {
    console.error('❌ GET /api/food', err);
    res.status(500).json({ error: 'Error al obtener alimentos' });
  }
});

/* ======================================================
 * POST /PatientMeals   (ObjectId cast + validación)
 * ==================================================== */
app.post('/PatientMeals', async (req: Request, res: Response) => {
  try {
    const { patient_id, name, ingredients, nutrients, instructions = '' } = req.body;
    if (!patient_id || !name || !Array.isArray(ingredients) || !nutrients)
      return res.status(400).json({ error: 'Campos obligatorios faltantes' });

    if (!Types.ObjectId.isValid(patient_id))
      return res.status(400).json({ error: 'patient_id inválido' });
    const pid = new Types.ObjectId(patient_id);

    const castIngredients = ingredients.map((ing: any) => {
      if (!ing.food_id || typeof ing.amount_g !== 'number' || ing.amount_g <= 0)
        throw new Error('Cada ingrediente necesita food_id y amount_g>0');
      if (!Types.ObjectId.isValid(ing.food_id))
        throw new Error(`food_id inválido: ${ing.food_id}`);
      return { food_id: new Types.ObjectId(ing.food_id), amount_g: ing.amount_g };
    });

    const requiredN = ['energy_kcal', 'protein_g', 'carbohydrates_g', 'fat_g', 'fiber_g', 'sugar_g'];
    for (const k of requiredN)
      if (typeof nutrients[k] !== 'number' || nutrients[k] < 0)
        return res.status(400).json({ error: `Nutriente ${k} debe ser numérico ≥0` });

    const meal = await PatientMeal.create({
      patient_id: pid,
      name: name.trim(),
      ingredients: castIngredients,
      nutrients,
      instructions: instructions.trim(),
    });
    res.status(201).json({ message: 'Comida creada', meal });
  } catch (err: any) {
    console.error('❌ POST /PatientMeals', err);
    res.status(500).json({ error: err.message || 'Error interno' });
  }
});

/* ==== GET /PatientMeals/:patient_id ==== */
app.get('/PatientMeals/:patient_id', async (req, res) => {
  const { patient_id } = req.params;
  if (!Types.ObjectId.isValid(patient_id))
    return res.status(400).json({ error: 'patient_id inválido' });
  const meals = await PatientMeal.find({ patient_id }).sort({ created_at: -1 }).lean();
  res.json(meals);
});

/* ==== Otros handlers (GET por id, PUT, DELETE)… usa mongoose.isValidObjectId y cast si editas) ==== 

// ------------ Mongo y server ------------
mongoose.connect(MONGODB_URI)
  .then(() => console.log('✅ Conectado a MongoDB Atlas'))
  .catch(err => { console.error('❌ MongoDB', err); process.exit(1); });

console.log('Voy a levantar Express…');
app.listen(PORT, () => console.log(`🚀 API corriendo en puerto ${PORT}`))
  .on('error', err => console.error('❌ Error al escuchar:', err));



// -----------------------------------*/

// 🚀 Arranque del servidor
app.listen(PORT, () => {
  console.log(`🚀 Servidor corriendo en http://localhost:${PORT}`);
});
