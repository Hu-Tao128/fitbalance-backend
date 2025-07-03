import axios from "axios";
import cors from 'cors';
import dotenv from 'dotenv';
import express, { Request, Response } from 'express';
import mongoose, { Document, Schema, Types } from 'mongoose';
import bcrypt from 'bcryptjs';

import nodemailer from 'nodemailer';
import crypto from 'crypto';

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

// Configuración del transporter de Nodemailer
const transporter = nodemailer.createTransport({
  service: process.env.EMAIL_SERVICE,
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS
  }
});

interface IPasswordResetToken extends Document {
  patient_id: Types.ObjectId;
  token: string;
  expiresAt: Date;
}

const PasswordResetTokenSchema = new Schema<IPasswordResetToken>({
  patient_id: { type: Schema.Types.ObjectId, required: true, ref: 'Patient' },
  token: { type: String, required: true },
  expiresAt: { type: Date, required: true, default: () => new Date(Date.now() + 3600000) } // 1 hora de expiración
}, { collection: 'PasswordResetTokens' });

const PasswordResetToken = mongoose.model<IPasswordResetToken>('PasswordResetToken', PasswordResetTokenSchema);

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

const Food = mongoose.model<IFood>(
  'Food',
  new mongoose.Schema({}, { strict: false, collection: 'Food' })
);

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

interface IMealFood {
  food_id: Types.ObjectId;
  grams: number;
  nutrients?: {
    calories?: number;
    protein?: number;
    fat?: number;
    carbs?: number;
  };
}

interface IMeal {
  type: 'breakfast' | 'lunch' | 'dinner' | 'snack';
  time: string;
  foods: IMealFood[];
  consumed?: boolean;
  notes?: string;
}

interface IDailyMealsLog extends Document {
  patient_id: Types.ObjectId;
  date: Date;
  totalCalories?: number;
  totalProtein?: number;
  totalFat?: number;
  totalCarbs?: number;
  meals: IMeal[];
  notes?: string;
}

const DailyMealsLogSchema = new Schema<IDailyMealsLog>({
  patient_id: { type: Schema.Types.ObjectId, required: true, ref: 'Patient' },
  date: { type: Date, required: true, index: true },
  totalCalories: { type: Number, min: 0 },
  totalProtein: { type: Number, min: 0 },
  totalFat: { type: Number, min: 0 },
  totalCarbs: { type: Number, min: 0 },
  meals: {
    type: [{
      type: {
        type: String,
        enum: ['breakfast', 'lunch', 'dinner', 'snack'],
        required: true
      },
      time: { type: String, required: true },
      foods: {
        type: [{
          food_id: { type: Schema.Types.ObjectId, required: true, ref: 'Food' },
          grams: { type: Number, required: true, min: 1 },
          nutrients: {
            calories: { type: Number, min: 0 },
            protein: { type: Number, min: 0 },
            fat: { type: Number, min: 0 },
            carbs: { type: Number, min: 0 }
          }
        }],
        required: true
      },
      consumed: { type: Boolean, default: false },
      notes: { type: String }
    }],
    default: []
  },
  notes: { type: String }
}, {
  collection: 'DailyMealsLogs',
  timestamps: true
});

const DailyMealsLog = mongoose.model<IDailyMealsLog>('DailyMealsLog', DailyMealsLogSchema);

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

// Función para calcular totales diarios
async function calculateDailyTotals(dailyLog: IDailyMealsLog) {
  let totalCalories = 0;
  let totalProtein = 0;
  let totalFat = 0;
  let totalCarbs = 0;

  // Obtener detalles de todos los alimentos
  const foodIds = dailyLog.meals.flatMap(meal => 
    meal.foods.map(food => food.food_id)
  );

  const foods = await Food.find({ 
    _id: { $in: foodIds } 
  }).lean();

  // Calcular nutrientes para cada comida
  for (const meal of dailyLog.meals) {
    for (const foodItem of meal.foods) {
      const food = foods.find(f => f._id.equals(foodItem.food_id));
      if (food) {
        const ratio = foodItem.grams / food.portion_size_g;
        
        // Usar nutrientes calculados si están disponibles, si no, calcularlos
        if (foodItem.nutrients?.calories) {
          totalCalories += foodItem.nutrients.calories;
        } else if (food.nutrients?.energy_kcal) {
          totalCalories += food.nutrients.energy_kcal * ratio;
        }

        if (foodItem.nutrients?.protein) {
          totalProtein += foodItem.nutrients.protein;
        } else if (food.nutrients?.protein_g) {
          totalProtein += food.nutrients.protein_g * ratio;
        }

        if (foodItem.nutrients?.fat) {
          totalFat += foodItem.nutrients.fat;
        } else if (food.nutrients?.fat_g) {
          totalFat += food.nutrients.fat_g * ratio;
        }

        if (foodItem.nutrients?.carbs) {
          totalCarbs += foodItem.nutrients.carbs;
        } else if (food.nutrients?.carbohydrates_g) {
          totalCarbs += food.nutrients.carbohydrates_g * ratio;
        }
      }
    }
  }

  // Actualizar totales
  dailyLog.totalCalories = Math.round(totalCalories);
  dailyLog.totalProtein = Math.round(totalProtein);
  dailyLog.totalFat = Math.round(totalFat);
  dailyLog.totalCarbs = Math.round(totalCarbs);
}

// Endpoint para obtener datos nutricionales diarios con objetivos
app.get('/daily-nutrition', async (req: Request, res: Response) => {
  try {
    const { patient_id, date } = req.query;

    if (!patient_id || !date) {
      return res.status(400).json({ error: 'Faltan parámetros: patient_id y date' });
    }

    if (!Types.ObjectId.isValid(patient_id as string)) {
      return res.status(400).json({ error: 'ID de paciente no válido' });
    }

    const logDate = new Date(date as string);
    const startOfDay = new Date(logDate.setHours(0, 0, 0, 0));
    const endOfDay = new Date(logDate.setHours(23, 59, 59, 999));

    // Buscar registro del día
    let dailyLog = await DailyMealsLog.findOne({
      patient_id: new Types.ObjectId(patient_id as string),
      date: { $gte: startOfDay, $lte: endOfDay }
    }).populate('meals.foods.food_id', 'name nutrients portion_size_g');

    // Si no hay registro, crear uno vacío
    if (!dailyLog) {
      dailyLog = new DailyMealsLog({
        patient_id: new Types.ObjectId(patient_id as string),
        date: startOfDay,
        meals: [],
        totalCalories: 0,
        totalProtein: 0,
        totalFat: 0,
        totalCarbs: 0
      });
    } else {
      // Calcular totales si no están calculados
      if (!dailyLog.totalCalories) {
        await calculateDailyTotals(dailyLog);
        await dailyLog.save();
      }
    }

    // Obtener el plan semanal más reciente para incluir objetivos
    const latestPlan = await WeeklyPlan.findOne({
      patient_id: new Types.ObjectId(patient_id as string)
    }).sort({ week_start: -1 }).lean();

    res.json({
      date: dailyLog.date,
      consumed: {
        calories: dailyLog.totalCalories || 0,
        protein: dailyLog.totalProtein || 0,
        fat: dailyLog.totalFat || 0,
        carbs: dailyLog.totalCarbs || 0
      },
      goals: {
        calories: latestPlan?.dailyCalories || 2000,
        protein: latestPlan?.protein || 150,
        fat: latestPlan?.fat || 70,
        carbs: latestPlan?.carbs || 250
      },
      meals: dailyLog.meals
    });
  } catch (error) {
    console.error('❌ Error en GET /daily-nutrition:', error);
    res.status(500).json({ error: 'Error al obtener los datos nutricionales' });
  }
});

// Endpoint para obtener el plan semanal más reciente
app.get('/weeklyplan/latest/:patient_id', async (req: Request, res: Response) => {
  const { patient_id } = req.params;

  if (!mongoose.Types.ObjectId.isValid(patient_id)) {
    return res.status(400).json({ error: 'ID de paciente no válido' });
  }

  try {
    const latestPlan = await WeeklyPlan.findOne({
      patient_id: new Types.ObjectId(patient_id),
    })
      .sort({ week_start: -1 })
      .lean();

    if (!latestPlan) {
      return res.status(404).json({ 
        message: 'No se encontró ningún plan semanal.',
        defaultValues: {
          dailyCalories: 2000,
          protein: 150,
          fat: 70,
          carbs: 250
        }
      });
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

// Login de paciente
app.post('/login', async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ message: 'Faltan campos: username y/o password' });
  }

  try {
    const patient = await Patient.findOne({ username }).select('+password');
    
    if (!patient) {
      return res.status(401).json({ message: 'Credenciales inválidas' });
    }

    const isMatch = await bcrypt.compare(password, patient.password);
    
    if (!isMatch) {
      return res.status(401).json({ message: 'Credenciales inválidas' });
    }

    const { password: _, ...patientData } = patient.toObject();
    
    res.json({
      message: 'Login exitoso',
      patient: patientData
    });
  } catch (err) {
    console.error('Error en login:', err);
    res.status(500).json({ error: 'Error del servidor' });
  }
});

// Obtener información de usuario
app.get('/user/:username', async (req, res) => {
  const { username } = req.params;

  try {
    const patient = await Patient.findOne({ username }).select('-password');

    if (!patient) {
      return res.status(404).json({ message: 'Usuario no encontrado' });
    }

    res.json(patient);
  } catch (err) {
    res.status(500).json({ error: 'Error al obtener datos del usuario' });
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

app.post('/send-reset-code', async (req: Request, res: Response) => {
  const { email } = req.body;

  if (!email) {
    return res.status(400).json({ message: 'El campo email es obligatorio.' });
  }

  try {
    const patient = await Patient.findOne({ email });

    if (!patient) {
      return res.status(404).json({ message: 'No se encontró un paciente con ese correo.' });
    }

    // Generar un token único de 6 dígitos
    const token = crypto.randomBytes(3).toString('hex'); // Ej: 'f3a1bc'

    // Guardar el token en la base de datos
    const resetToken = new PasswordResetToken({
      patient_id: patient._id,
      token,
      expiresAt: new Date(Date.now() + 60 * 60 * 1000) // 1 hora
    });

    await resetToken.save();

    // Enviar el correo
    const mailOptions = {
      from: process.env.EMAIL_USER,
      to: email,
      subject: 'Código de recuperación - Nutifrut',
      text: `Hola ${patient.name},\n\nTu código de recuperación es: ${token}\nEste código expira en 1 hora.\n\nAtentamente,\nEl equipo de Nutifrut.`
    };

    await transporter.sendMail(mailOptions);

    res.json({ message: 'Código de recuperación enviado al correo del paciente.' });
  } catch (error) {
    console.error('❌ Error al enviar el código de recuperación:', error);
    res.status(500).json({ error: 'Error al enviar el correo de recuperación.' });
  }
});

// 🚀 Arranque del servidor
app.listen(PORT, () => {
  console.log(`🚀 Servidor corriendo en http://localhost:${PORT}`);
});