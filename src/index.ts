import axios from "axios";
import bcrypt from 'bcryptjs';
import cors from 'cors';
import dotenv from 'dotenv';
import express, { Request, Response } from 'express';
import mongoose, { Document, Schema, Types } from 'mongoose';

import crypto from 'crypto';
import nodemailer from 'nodemailer';
import { DateTime } from 'luxon';

function nowInTijuana() {
  return DateTime.now().setZone('America/Tijuana');
}

function todayStartInTijuana() {
  return nowInTijuana().startOf('day').toJSDate();
}

function todayEndInTijuana() {
  return nowInTijuana().endOf('day').toJSDate();
}

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

// 🔌 Conexión a MongoDB
mongoose.connect(MONGODB_URI)
  .then(() => {
    console.log('Conectado a MongoDB Atlas');
    app.listen(PORT, () => {
      console.log(`Servidor corriendo en http://localhost:${PORT}`);
    });
  })
  .catch((err) => {
    console.error('❌ Error al conectar a MongoDB:', err);
    process.exit(1);
  });

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

interface FoodItem {
  food_id: mongoose.Schema.Types.ObjectId;
  grams: number;
}


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
  _id?: Types.ObjectId;
  day: string;
  type: 'breakfast' | 'lunch' | 'dinner' | 'snack';
  time: string;
  foods: IMealFood[];
  consumed?: boolean;
  notes?: string;
}

interface IDailyMealLog extends Document {
  patient_id: Types.ObjectId;
  date: Date;
  totalCalories?: number;
  totalProtein?: number;
  totalFat?: number;
  totalCarbs?: number;
  caloriesConsumed?: number;
  meals: IMeal[];
  notes?: string;
}

const DailyMealLogSchema = new Schema<IDailyMealLog>({
  patient_id: { type: Schema.Types.ObjectId, required: true, ref: 'Patient' },
  date: { type: Date, required: true, index: true },
  totalCalories: { type: Number, min: 0 },
  totalProtein: { type: Number, min: 0 },
  totalFat: { type: Number, min: 0 },
  totalCarbs: { type: Number, min: 0 },
  caloriesConsumed: { type: Number, min: 0 },
  meals: {
    type: [{
      day: {
        type: String,
        enum: ['monday', 'tuesday', 'wednesday', 'thursday', 'friday', 'saturday', 'sunday'],
        required: true,
      },
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
  collection: 'DailyMealLogs',
  timestamps: true
});

const DailyMealLog = mongoose.model<IDailyMealLog>('DailyMealLog', DailyMealLogSchema);

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
// Nueva función de búsqueda usando el endpoint 'instant' de Nutritionix
async function searchNutritionixForList(query: string) {
  const response = await axios.get(
    'https://trackapi.nutritionix.com/v2/search/instant',
    {
      params: {
        query: query
      },
      headers: {
        'x-app-id': NUTRITIONIX_APP_ID,
        'x-app-key': NUTRITIONIX_APP_KEY,
      },
    }
  );
  // La respuesta de esta API tiene resultados comunes ('common') y de marcas ('branded')
  return [...(response.data.common || []), ...(response.data.branded || [])];
}

// 🧠 Ruta combinada de búsqueda nutricional
app.post('/search-food', async (req: Request, res: Response) => {
  const { query } = req.body;

  if (!query) {
    return res.status(400).json({ error: 'Falta el parámetro "query"' });
  }

  try {
    // Llama a la nueva función de búsqueda de Nutritionix
    const foodList = await searchNutritionixForList(query);

    if (foodList && foodList.length > 0) {
      return res.json({
        source: 'nutritionix',
        // Devuelve solo los primeros 3 resultados
        results: foodList.slice(0, 3)
      });
    }

    return res.status(404).json({ message: 'No se encontraron alimentos con ese nombre.' });

  } catch (error: any) {
    console.error('❌ Error en /search-food:', error.message);
    return res.status(500).json({ error: 'Error en la búsqueda de alimentos' });
  }
});

// Función para calcular totales diarios
async function calculateDailyTotals(dailyLog: IDailyMealLog) {
  let totalCalories = 0;
  let totalProtein = 0;
  let totalFat = 0;
  let totalCarbs = 0;

  // Obtener detalles de todos los alimentos
  const foodIds = dailyLog.meals.flatMap(meal =>
    meal.foods.map(food => new Types.ObjectId(food.food_id))
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

  const roundedCalories = Math.round(totalCalories || 0);
  
  // Actualizar totales
  dailyLog.totalCalories = Math.round(totalCalories || 0);
  dailyLog.totalProtein = Math.round(totalProtein || 0);
  dailyLog.totalFat = Math.round(totalFat || 0);
  dailyLog.totalCarbs = Math.round(totalCarbs || 0);
  dailyLog.caloriesConsumed = dailyLog.totalCalories;

}

// Endpoint existente (/daily-nutrition) - Versión corregida
app.get("/daily-nutrition", async (req: Request, res: Response) => {
  try {
    const { patient_id, date } = req.query;
    if (!patient_id || !date) {
      return res.status(400).json({ error: "Missing patient_id or date" });
    }

    const pid = new Types.ObjectId(patient_id as string);
    const inputDate = new Date(date as string);

    // Normalizar fecha (a medianoche)
    const startOfDay = new Date(inputDate);
    startOfDay.setHours(0, 0, 0, 0);
    const endOfDay = new Date(startOfDay);
    endOfDay.setHours(23, 59, 59, 999);

    // Buscar documento existente (usando el rango correcto)
    let log = await DailyMealLog.findOne({
      patient_id: pid,
      date: { $gte: startOfDay, $lte: endOfDay }
    });

    if (!log) {
      // Crear nuevo documento con fecha normalizada (si no existe)
      log = new DailyMealLog({
        patient_id: pid,
        date: startOfDay, // ← Fecha normalizada aquí
        meals: [],
        totalCalories: 0,
        totalProtein: 0,
        totalFat: 0,
        totalCarbs: 0,
        caloriesConsumed: 0
      });
      await log.save();
    }

    // Resto de tu lógica...
    res.json({
      date: log.date,
      consumed: {
        calories: log.totalCalories || 0,
        protein: log.totalProtein || 0,
        fat: log.totalFat || 0,
        carbs: log.totalCarbs || 0,
      },
      meals: log.meals,
    });
  } catch (error: any) {
    console.error('❌ Error en /daily-nutrition:', error);
    res.status(500).json({ error: "Internal server error" });
  }
});

// Endpoint to get the latest weekly plan
app.get('/weeklyplan/latest/:patient_id', async (req: Request, res: Response) => {
  const { patient_id } = req.params;

  if (!mongoose.Types.ObjectId.isValid(patient_id)) {
    return res.status(400).json({ error: 'Invalid patient ID' });
  }

  try {
    const latestPlan = await WeeklyPlan.findOne({
      patient_id: new Types.ObjectId(patient_id),
    })
      .sort({ week_start: -1 })
      .lean();

    if (!latestPlan) {
      // ✅ CORRECTED: Always return a 200 OK status.
      // This indicates the request was successful, even if no plan was found.
      return res.status(200).json({
        message: 'No weekly plan found.',
        // Provide default values so the frontend has something to work with.
        dailyCalories: 2000,
        protein: 150,
        fat: 70,
        carbs: 250
      });
    }

    return res.json(latestPlan);

  } catch (error) {
    console.error('❌ Error in /weeklyplan/latest:', error);
    return res.status(500).json({ error: 'Error getting the latest weekly plan' });
  }
});

app.get('/weeklyplan/daily/:patient_id', async (req, res) => {
  try {
    let patientId = req.params.patient_id;
    patientId = patientId.replace(/\.$/, '');

    const plan = await WeeklyPlan.findOne({ patient_id: patientId })
      .sort({ week_start: -1 })
      .lean();

    if (!plan) {
      return res.status(404).json({ message: 'Plan no encontrado' });
    }

    // Obtener la fecha actual en la zona horaria de Tijuana
    const todayInTijuana = nowInTijuana();
    const todayWeekDay = todayInTijuana.weekdayLong!.toLowerCase();
    console.log(todayInTijuana, todayWeekDay);
    const todayDate = todayInTijuana.startOf('day').toJSDate(); // Si luego la necesitas como Date nativo

    // Retorna 'monday', 'tuesday', etc. (en inglés y lowercase, ideal para tu lógica)

    const todayMeals = plan.meals.filter(meal => meal.day === todayWeekDay);

    const enrichedMeals = await Promise.all(todayMeals.map(async (meal) => {
      const enrichedFoods = await Promise.all(meal.foods.map(async (item) => {
        const food = await Food.findById(item.food_id).lean();
        return {
          ...item,
          name: food?.name || 'Desconocido'
        };
      }));

      return {
        ...meal,
        foods: enrichedFoods
      };
    }));

    res.json({ ...plan, meals: enrichedMeals });

  } catch (err) {
    console.error('Error al obtener el plan diario:', err);
    res.status(500).json({ message: 'Error interno del servidor' });
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
    const token = crypto.randomBytes(3).toString('hex');

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

interface IPatientMeal extends Document {
  patient_id: Types.ObjectId;
  name: string;
  ingredients: {
    food_id: Types.ObjectId; // Referencia al _id del alimento en la colección Food
    amount_g: number;
  }[];
  nutrients: {
    energy_kcal: number;
    protein_g: number;
    carbohydrates_g: number;
    fat_g: number;
    fiber_g: number;
    sugar_g: number;
  };
  instructions?: string;
  created_at: Date; // Usamos created_at para coincidir con tu esquema
  updated_at: Date; // Usamos updated_at para coincidir con tu esquema
}

const PatientMealSchema = new Schema<IPatientMeal>({
  patient_id: { type: Schema.Types.ObjectId, required: true, ref: 'Patient' },
  name: { type: String, required: true },
  ingredients: [{
    food_id: { type: Schema.Types.ObjectId, required: true, ref: 'Food' },
    amount_g: { type: Number, required: true, min: 1 },
  }],
  nutrients: {
    energy_kcal: { type: Number, required: true, min: 0 },
    protein_g: { type: Number, required: true, min: 0 },
    carbohydrates_g: { type: Number, required: true, min: 0 },
    fat_g: { type: Number, required: true, min: 0 },
    fiber_g: { type: Number, required: true, min: 0 },
    sugar_g: { type: Number, required: true, min: 0 },
  },
  instructions: { type: String },
  created_at: { type: Date, default: Date.now },
  updated_at: { type: Date, default: Date.now },
}, {
  collection: 'PatientMeals', // Coincide con el nombre de tu colección
  timestamps: { createdAt: 'created_at', updatedAt: 'updated_at' } // Mongoose maneja estos campos automáticamente
});

const PatientMeal = mongoose.model<IPatientMeal>('PatientMeal', PatientMealSchema);

app.post('/PatientMeals', async (req: Request, res: Response) => {
  const { patient_id, name, ingredients, nutrients, instructions } = req.body;

  if (!patient_id || !name || !ingredients || ingredients.length === 0 || !nutrients) {
    return res.status(400).json({ error: 'Faltan campos obligatorios o la lista de ingredientes está vacía.' });
  }
  if (!mongoose.Types.ObjectId.isValid(patient_id)) {
    return res.status(400).json({ error: 'ID de paciente no válido.' });
  }

  try {
    const newMeal = new PatientMeal({
      patient_id: new mongoose.Types.ObjectId(patient_id),
      name,
      ingredients: ingredients.map((ing: any) => ({
        food_id: new mongoose.Types.ObjectId(ing.food_id),
        amount_g: ing.amount_g,
      })),
      nutrients,
      instructions,
    });

    await newMeal.save();
    res.status(201).json({ message: 'Comida personalizada creada con éxito', meal: newMeal });
  } catch (error) {
    console.error('❌ Error al crear comida personalizada:', error);
    res.status(500).json({ error: 'Error interno del servidor al crear comida.' });
  }
});

// 👉 Endpoint para obtener todas las comidas personalizadas de un paciente (GET /PatientMeals/:patient_id)
app.get('/PatientMeals/:patient_id', async (req: Request, res: Response) => {
  const { patient_id } = req.params;

  if (!mongoose.Types.ObjectId.isValid(patient_id)) {
    return res.status(400).json({ error: 'ID de paciente no válido.' });
  }

  try {
    const meals = await PatientMeal.find({ patient_id: new mongoose.Types.ObjectId(patient_id) })
      .populate('ingredients.food_id', 'name portion_size_g nutrients'); // Popula para obtener detalles del alimento

    res.json(meals);
  } catch (error) {
    console.error('❌ Error al obtener comidas personalizadas:', error);
    res.status(500).json({ error: 'Error interno del servidor al obtener comidas.' });
  }
});

// 👉 Endpoint para actualizar una comida personalizada (PUT /PatientMeals/:meal_id)
app.put('/PatientMeals/:meal_id', async (req: Request, res: Response) => {
  const { meal_id } = req.params;
  const { name, ingredients, nutrients, instructions } = req.body;

  if (!mongoose.Types.ObjectId.isValid(meal_id)) {
    return res.status(400).json({ error: 'ID de comida no válido.' });
  }
  if (!name || !ingredients || ingredients.length === 0 || !nutrients) {
    return res.status(400).json({ error: 'Faltan campos obligatorios o la lista de ingredientes está vacía.' });
  }

  try {
    const updatedMeal = await PatientMeal.findByIdAndUpdate(
      meal_id,
      {
        name,
        ingredients: ingredients.map((ing: any) => ({
          food_id: new mongoose.Types.ObjectId(ing.food_id),
          amount_g: ing.amount_g,
        })),
        nutrients,
        instructions,
        updated_at: new Date() // Actualiza la fecha de modificación
      },
      { new: true } // Retorna el documento actualizado
    );

    if (!updatedMeal) {
      return res.status(404).json({ message: 'Comida personalizada no encontrada.' });
    }
    res.json({ message: 'Comida personalizada actualizada con éxito', meal: updatedMeal });
  } catch (error) {
    console.error('❌ Error al actualizar comida personalizada:', error);
    res.status(500).json({ error: 'Error interno del servidor al actualizar comida.' });
  }
});

// 👉 Endpoint para eliminar una comida personalizada (DELETE /PatientMeals/:meal_id)
app.delete('/PatientMeals/:meal_id', async (req: Request, res: Response) => {
  const { meal_id } = req.params;

  if (!mongoose.Types.ObjectId.isValid(meal_id)) {
    return res.status(400).json({ error: 'ID de comida no válido.' });
  }

  try {
    const deletedMeal = await PatientMeal.findByIdAndDelete(meal_id);
    if (!deletedMeal) {
      return res.status(404).json({ message: 'Comida personalizada no encontrada.' });
    }
    res.json({ message: 'Comida personalizada eliminada con éxito.' });
  } catch (error) {
    console.error('❌ Error al eliminar comida personalizada:', error);
    res.status(500).json({ error: 'Error interno del servidor al eliminar comida.' });
  }
});

interface PopulatedFood {
  _id: Types.ObjectId;
  name: string;
  portion_size_g?: number;
  nutrients?: {
    calories?: number;
    protein?: number;
    fat?: number;
    carbs?: number;
  };
}

interface PopulatedIngredient {
  food_id: PopulatedFood; // ya no es ObjectId
  amount_g: number;
}

interface PopulatedPatientMeal extends Omit<IPatientMeal, 'ingredients'> {
  ingredients: PopulatedIngredient[];
}

// 👉 Endpoint para añadir una comida personalizada al DailyMealLog 
app.post("/DailyMealLogs/add-custom-meal", async (req: Request, res: Response) => {
  const { patient_id, meal_id, type, time } = req.body;

  if (!patient_id || !meal_id || !type || !time) {
    return res.status(400).json({ error: "Faltan campos obligatorios" });
  }

  try {
    const patientMeal = await PatientMeal
      .findById(meal_id)
      .populate("ingredients.food_id", "name nutrients portion_size_g")
      .lean() as PopulatedPatientMeal | null;

    if (!patientMeal) {
      return res.status(404).json({ message: "Comida personalizada no encontrada." });
    }

    if (String(patientMeal.patient_id) !== patient_id) {
      return res.status(403).json({ message: "No puedes usar una comida que no te pertenece." });
    }

    const today = new Date();
    today.setHours(0, 0, 0, 0);

    let dailyLog = await DailyMealLog.findOne({ patient_id, date: today });

    if (!dailyLog) {
      dailyLog = new DailyMealLog({
        patient_id,
        date: today,
        meals: [],
        totalCalories: 0,
        totalProtein: 0,
        totalFat: 0,
        totalCarbs: 0,
        caloriesConsumed: 0, // obligatorio según tu JSON schema
      });
    }

    function getTodayWeekday(): string {
      return new Date().toLocaleDateString('en-US', { weekday: 'long' }).toLowerCase();
    }

    dailyLog.meals.push({
      day: getTodayWeekday(),
      type,
      time,
      foods: patientMeal.ingredients.map((ing) => ({
        food_id: ing.food_id._id,
        grams: Math.round(ing.amount_g),
      })),
      consumed: true,
      notes: `Comida personalizada: ${patientMeal.name}`,
    });

    await calculateDailyTotals(dailyLog);
    await dailyLog.save();

    res.status(200).json({ message: "Comida añadida al log diario", dailyLog });
  } catch (err) {
    console.error("Error en /DailyMealLogs/add-custom-meal:", err);
    res.status(500).json({ error: "Error al añadir la comida al log diario" });
  }
});

// obtener todos los registros de DailyMealLogs de un paciente (para estadísticas)
app.get('/daily-meal-logs/all/:patient_id', async (req: Request, res: Response) => {
  const { patient_id } = req.params;

  if (!mongoose.Types.ObjectId.isValid(patient_id)) {
    return res.status(400).json({ error: 'ID de paciente no válido' });
  }

  try {
    const pid = new Types.ObjectId(patient_id);
    const logs = await DailyMealLog.find({ patient_id: pid })
      .sort({ date: -1 })
      .lean();

    if (!logs || logs.length === 0) {
      return res.json([]);
    }

    // Asegúrate de que los totales estén calculados
    const logsWithTotals = await Promise.all(logs.map(async log => {
      if (
        log.totalCalories !== undefined &&
        log.totalProtein  !== undefined &&
        log.totalFat      !== undefined &&
        log.totalCarbs    !== undefined
      ) return log;
      const logDoc = new DailyMealLog(log);
      await calculateDailyTotals(logDoc);
      return logDoc.toObject();
    }));

    // Aquí usamos parseLocalDate para “borrar” el offset y que tu front reciba
    // un Date a medianoche de tu zona (o una cadena YYYY-MM-DD si prefieres)
    const formattedLogs = logsWithTotals.map(log => ({
      // si quieres devolver Date:
      date: DateTime.fromJSDate(log.date).setZone('America/Tijuana').toISODate(),      // — o si prefieres string 'YYYY-MM-DD':
      // date: parseLocalDate(log.date).toISOString().split('T')[0],

      totals: {
        calories: log.totalCalories || 0,
        protein:  log.totalProtein   || 0,
        fat:      log.totalFat       || 0,
        carbs:    log.totalCarbs     || 0,
      },
      meals: log.meals,
      notes: log.notes
    }));

    res.json(formattedLogs);

  } catch (error: any) {
    console.error('❌ Error en /daily-meal-logs/all:', error);
    res.status(500).json({ error: 'Error al obtener los registros de comidas' });
  }
});

// Endpoint unificado para obtener/crear registro diario
app.get('/daily-meal-logs/today/:patient_id', async (req: Request, res: Response) => {
  const { patient_id } = req.params;

  if (!mongoose.Types.ObjectId.isValid(patient_id)) {
    return res.status(400).json({ error: 'ID de paciente no válido' });
  }

  try {
    const pid = new Types.ObjectId(patient_id);
    const nowTz     = DateTime.now().setZone('America/Tijuana');
    const todayStart= nowTz.startOf('day').toJSDate();   // 00:00 Tijuana
    const todayEnd  = nowTz.endOf('day').toJSDate();     // 23:59:59.999 Tijuana

    // 2. Buscar registro existente
    let log = await DailyMealLog.findOne({
      patient_id: pid,
      date: { $gte: todayStart, $lte: todayEnd }
    });

    // 3. Si no existe, crear uno nuevo 
    if (!log) {
      log = new DailyMealLog({
        patient_id: pid,
        date: todayStart,
        meals: [],
        totalCalories: 0,
        totalProtein: 0,
        totalFat: 0,
        totalCarbs: 0,
        caloriesConsumed: 0
      });
      await log.save();
    }

    // 4. Calcular totales si faltan (por si acaso)
    if (log.totalCalories === undefined) {
      await calculateDailyTotals(log);
      await log.save();
    }

    // 5. Formatear respuesta
    const response = {
      date: log.date,
      totals: {
        calories: log.totalCalories || 0,
        protein:  log.totalProtein   || 0,
        fat:      log.totalFat       || 0,
        carbs:    log.totalCarbs     || 0,
      },
      meals: log.meals,
      notes: log.notes
    };

    res.json(response);

  } catch (error: any) {
    console.error('❌ Error en /daily-meal-logs/today:', error);
    res.status(500).json({
      error: 'Error al obtener/crear registro diario',
      details: error.message
    });
  }
});

// Endpoint: añade una comida del WeeklyPlan al DailyMealLog
app.post("/DailyMealLogs/add-weekly-meal", async (req: Request, res: Response) => {
  const { patient_id, meal } = req.body;

  if (!patient_id || !meal) {
    return res.status(400).json({ error: "Faltan datos obligatorios (patient_id, meal)" });
  }

  try {
    const today = todayStartInTijuana();
    today.setHours(0, 0, 0, 0);

    // Buscar o crear el log diario
    let dailyLog = await DailyMealLog.findOne({ patient_id, date: today });
    if (!dailyLog) {
      dailyLog = new DailyMealLog({
        patient_id,
        date: today,
        meals: [],
        totalCalories: 0,
        totalProtein: 0,
        totalFat: 0,
        totalCarbs: 0,
        caloriesConsumed: 0,
      });
    }

    // Evitar duplicar comidas
    const alreadyExists = dailyLog.meals.some(
      (m) => m.type === meal.type && m.time === meal.time
    );
    if (alreadyExists) {
      return res.status(400).json({ error: "Esta comida ya fue añadida." });
    }

    dailyLog.meals.push({
      day: meal.day,
      type: meal.type,
      time: meal.time,
      foods: meal.foods.map((f: any) => ({
        food_id: f.food_id,
        grams: f.grams,
      })),
      consumed: true,
      notes: `Comida añadida desde el WeeklyPlan`,
    });

    await calculateDailyTotals(dailyLog);
    await dailyLog.save();

    res.status(200).json({ message: "Comida del plan añadida al log diario", dailyLog });
  } catch (err) {
    console.error("Error en /DailyMealLogs/add-weekly-meal:", err);
    res.status(500).json({ error: "Error al añadir la comida al log diario" });
  }
});


//
// --------------------------------------------
//

app.post('/dailymeallogs/add-food', async (req: Request, res: Response) => {
  const { patient_id, type, time, food_data } = req.body;

  if (!patient_id || !type || !time || !food_data || !food_data.food_name) {
    return res.status(400).json({ error: "Faltan campos obligatorios." });
  }

  try {
    const foodToSave = {
      name: food_data.food_name,
      portion_size_g: food_data.serving_weight_grams || 100,
      category: food_data.category || 'general',
      nutrients: {
        energy_kcal: food_data.nf_calories || 0,
        protein_g: food_data.nf_protein || 0,
        carbohydrates_g: food_data.nf_total_carbohydrate || 0,
        fat_g: food_data.nf_total_fat || 0,
        fiber_g: food_data.nf_dietary_fiber || 0,
        sugar_g: food_data.nf_sugars || 0,
      }
    };

    const savedFood = await Food.findOneAndUpdate(
      { name: foodToSave.name, portion_size_g: foodToSave.portion_size_g },
      { $set: foodToSave },
      { new: true, upsert: true, runValidators: true }
    );

    const today = todayStartInTijuana();
    today.setHours(0, 0, 0, 0);

    let dailyLog = await DailyMealLog.findOne({
      patient_id: new mongoose.Types.ObjectId(patient_id),
      date: today
    });

    if (!dailyLog) {
      dailyLog = new DailyMealLog({
        patient_id: new mongoose.Types.ObjectId(patient_id),
        date: today,
        meals: [],
        caloriesConsumed: 0,
        proteinConsumed: 0,
        fatConsumed: 0,
        carbsConsumed: 0
      });
    }

    function getTodayWeekday(): IMeal['day'] {
      return new Date().toLocaleDateString('en-US', { weekday: 'long' }).toLowerCase() as IMeal['day'];
    }

    dailyLog.meals.push({
      day: getTodayWeekday(),
      type,
      time,
      foods: [{
        food_id: savedFood._id,
        grams: Math.max(1, Math.round(savedFood.portion_size_g)),
      }],
      consumed: true,
      notes: savedFood.name,
    });

    await calculateDailyTotals(dailyLog);
    await dailyLog.save();

    res.status(200).json({ message: "Alimento añadido al log diario", dailyLog });

  } catch (err: any) {
    console.error("❌ Error en /dailymeallogs/add-food:", err.code === 121 ? err.errInfo : err);
    res.status(500).json({
      error: "Error interno al añadir el alimento.",
      details: err.message
    });
  }
});



// EDITAR PEFIL------------------------
app.put('/patient/:id', async (req: Request, res: Response) => {
  const { id } = req.params;
  const updateData = req.body;

  if (!mongoose.Types.ObjectId.isValid(id)) {
    return res.status(400).json({ error: 'ID de paciente no válido' });
  }

  // No permitir la actualización de campos sensibles como el username o la contraseña desde aquí
  delete updateData.username;
  delete updateData.password;

  try {
    const updatedPatient = await Patient.findByIdAndUpdate(
      id,
      { $set: updateData },
      { new: true, runValidators: true } // new: true devuelve el documento actualizado
    ).select('-password'); // Excluir la contraseña de la respuesta

    if (!updatedPatient) {
      return res.status(404).json({ message: 'Paciente no encontrado' });
    }

    res.json({ message: 'Perfil actualizado con éxito', patient: updatedPatient });
  } catch (error) {
    console.error('❌ Error al actualizar el perfil:', error);
    res.status(500).json({ error: 'Error interno del servidor al actualizar el perfil' });
  }
});


// --------------------------

//  CITAS ------------------------

// -------------------

interface IAppointment extends Document {
  nutritionist_id: Types.ObjectId;
  patient_id: Types.ObjectId;
  appointment_date: Date;
  appointment_time: string;
  appointment_type?: string;
  status: 'scheduled' | 'completed' | 'cancelled';
  notes?: string;
}

const AppointmentSchema = new Schema<IAppointment>({
  nutritionist_id: { type: Schema.Types.ObjectId, required: true, ref: 'Nutritionist' }, // Asumiendo que tienes un modelo Nutritionist
  patient_id: { type: Schema.Types.ObjectId, required: true, ref: 'Patient' },
  appointment_date: { type: Date, required: true },
  appointment_time: { type: String, required: true },
  appointment_type: { type: String },
  status: { type: String, enum: ['scheduled', 'completed', 'cancelled'], required: true },
  notes: { type: String }
}, {
  collection: 'Appointments', // Nombre de tu colección en MongoDB
  timestamps: { createdAt: 'created_at', updatedAt: 'updated_at' }
});

const Appointment = mongoose.model<IAppointment>('Appointment', AppointmentSchema);

// ... (antes de tus endpoints de app.get, app.post, etc.)

// index.ts (backend)

app.get('/appointments/:patient_id', async (req: Request, res: Response) => {
  const { patient_id } = req.params;

  // Log en el servidor para ver qué ID llega
  console.log(`Backend: Buscando citas para el patient_id: ${patient_id}`);

  if (!mongoose.Types.ObjectId.isValid(patient_id)) {
    console.log('Backend: El ID recibido no es válido.');
    return res.status(400).json({ error: 'ID de paciente no válido' });
  }

  try {
    const appointments = await Appointment.find({ patient_id: new Types.ObjectId(patient_id) });

    // Log en el servidor para ver cuántas citas se encontraron
    console.log(`Backend: Se encontraron ${appointments.length} citas.`);

    // Devuelve 200 OK y un array (vacío o con datos). Esto es mejor que un 404.
    // Así, la app sabrá que la consulta fue exitosa aunque no haya resultados.
    res.status(200).json(appointments);

  } catch (error) {
    console.error('❌ Backend: Error en /appointments/:patient_id:', error);
    res.status(500).json({ error: 'Error al obtener las citas' });
  }
});


// 

//  -------------------------- VER LOS DATOS DEL NUTRIOLOGO -------------------------


// 👇 ADD THIS NEW MODEL FOR NUTRITIONISTS
interface INutritionist extends Document {
  _id: Types.ObjectId;
  name: string;
  lastName: string;
  secondLastName?: string;
  email: string;
  password?: string;
  city: string;
  street: string;
  neighborhood: string;
  streetNumber: string;
  licenseNumber?: string;
  specialization?: string;
  isActive: boolean;
}

const NutritionistSchema = new Schema<INutritionist>({
  name: { type: String, required: true },
  lastName: { type: String, required: true },
  secondLastName: { type: String },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true, select: false },
  city: { type: String, required: true },
  street: { type: String, required: true },
  neighborhood: { type: String, required: true },
  streetNumber: { type: String, required: true },
  licenseNumber: { type: String },
  specialization: { type: String },
  isActive: { type: Boolean, default: true },
}, {
  collection: 'Nutritionist',
  timestamps: { createdAt: 'createdAt', updatedAt: 'updatedAt' }
});

const Nutritionist = mongoose.model<INutritionist>('Nutritionist', NutritionistSchema);


// 👇 ADD THIS NEW ENDPOINT
// In your backend index.ts file...

app.get('/nutritionist/:id', async (req: Request, res: Response) => {
  const { id } = req.params;

  // --- LOGS FOR DEBUGGING ---
  console.log('--- PETICIÓN RECIBIDA EN /nutritionist/:id ---');
  console.log(`1. ID Recibido del request: ${id}`);

  if (!mongoose.Types.ObjectId.isValid(id)) {
    console.log('2. El ID no es válido. Devolviendo error 400.');
    return res.status(400).json({ error: 'Invalid nutritionist ID' });
  }

  try {
    console.log('2. El ID es válido. Buscando en la base de datos...');
    const nutritionist = await Nutritionist.findById(id).select('-password');

    console.log('3. Resultado de la búsqueda:', nutritionist); // This is the most important log

    if (!nutritionist) {
      console.log('4. Nutriólogo no encontrado en la base de datos. Devolviendo error 404.');
      return res.status(404).json({ message: 'Nutritionist not found in DB.' });
    }

    console.log('4. Nutriólogo ENCONTRADO. Devolviendo datos.');
    res.json(nutritionist);

  } catch (error) {
    console.error('❌ Error en el bloque try/catch:', error);
    return res.status(500).json({ error: 'Internal server error while fetching nutritionist.' });
  }
});


// -------------------------

// DASHBOARD DAILYMEAL MANAGE

// ----------------------

// In your backend index.ts file...

// 1.A: Endpoint to get a specific DailyMealLog by date
// En tu backend index.ts

app.get('/daily-meal-logs/by-date', async (req: Request, res: Response) => {
  const { patient_id, date } = req.query;

  if (!patient_id || !date) {
    return res.status(400).json({ error: 'patient_id and date are required query parameters.' });
  }
  if (!mongoose.Types.ObjectId.isValid(patient_id as string)) {
    return res.status(400).json({ error: 'Invalid patient ID.' });
  }

  try {
    const searchDate = new Date(date as string);
    const startOfDay = new Date(searchDate.setHours(0, 0, 0, 0));
    const endOfDay = new Date(searchDate.setHours(23, 59, 59, 999));

    const log = await DailyMealLog.findOne({
      patient_id: new Types.ObjectId(patient_id as string),
      date: { $gte: startOfDay, $lte: endOfDay }
    }).populate('meals.foods.food_id', 'name');

    if (!log) {
      return res.json({
        _id: null, // Para días sin registro, el _id es null (y el botón no aparecerá)
        date: startOfDay,
        meals: [],
        totals: { calories: 0, protein: 0, fat: 0, carbs: 0 }
      });
    }

    // ✅ ASEGÚRATE DE QUE TU RESPUESTA INCLUYA EL _id DEL LOG
    res.json({
      _id: log._id, // <-- ¡ESTA LÍNEA ES LA MÁS IMPORTANTE!
      date: log.date,
      meals: log.meals,
      totals: {
        calories: log.totalCalories || 0,
        protein: log.totalProtein || 0,
        fat: log.totalFat || 0,
        carbs: log.totalCarbs || 0,
      }
    });

  } catch (error) {
    console.error('❌ Error in /daily-meal-logs/by-date:', error);
    res.status(500).json({ error: 'Server error fetching daily log.' });
  }
});

// 1.B: Endpoint to delete a specific meal from a DailyMealLog


app.get('/daily-meal-logs/by-date', async (req: Request, res: Response) => {
  const { patient_id, date } = req.query;

  if (!patient_id || !date) {
    return res.status(400).json({ error: 'patient_id and date are required query parameters.' });
  }
  if (!mongoose.Types.ObjectId.isValid(patient_id as string)) {
    return res.status(400).json({ error: 'Invalid patient ID.' });
  }

  try {
    const searchDate = new Date(date as string);
    const startOfDay = new Date(searchDate.setHours(0, 0, 0, 0));
    const endOfDay = new Date(searchDate.setHours(23, 59, 59, 999));

    const log = await DailyMealLog.findOne({
      patient_id: new Types.ObjectId(patient_id as string),
      date: { $gte: startOfDay, $lte: endOfDay }
    }).populate('meals.foods.food_id', 'name');

    if (!log) {
      return res.json({
        _id: null,
        date: startOfDay,
        meals: [],
        totals: { calories: 0, protein: 0, fat: 0, carbs: 0 }
      });
    }

    // ✅ CORRECCIÓN FINAL: Se añade el _id del log a la respuesta.
    res.json({
      _id: log._id, // <-- ¡LA LÍNEA QUE FALTABA!
      date: log.date,
      meals: log.meals,
      totals: {
        calories: log.totalCalories || 0,
        protein: log.totalProtein || 0,
        fat: log.totalFat || 0,
        carbs: log.totalCarbs || 0,
      }
    });

  } catch (error) {
    console.error('❌ Error in /daily-meal-logs/by-date:', error);
    res.status(500).json({ error: 'Server error fetching daily log.' });
  }
});

// En tu backend index.ts

app.delete('/daily-meal-logs/:logId/meals/:mealId', async (req: Request, res: Response) => {
  const { logId, mealId } = req.params;

  if (!mongoose.Types.ObjectId.isValid(logId) || !mongoose.Types.ObjectId.isValid(mealId)) {
    return res.status(400).json({ error: 'Invalid Log ID or Meal ID.' });
  }

  try {
    // Usamos el operador $pull de MongoDB para eliminar el subdocumento del arreglo.
    // Esto es más directo y atómico que buscar, filtrar y guardar.
    const updatedLog = await DailyMealLog.findByIdAndUpdate(
      logId,
      { $pull: { meals: { _id: mealId } } },
      { new: true } // Esta opción hace que nos devuelva el documento ya actualizado.
    );

    if (!updatedLog) {
      return res.status(404).json({ error: 'Daily log not found.' });
    }

    // Después de la eliminación, recalculamos los totales.
    await calculateDailyTotals(updatedLog);

    // Guardamos el documento con los nuevos totales.
    const finalLog = await updatedLog.save();

    res.json({ message: 'Meal deleted successfully.', dailyLog: finalLog });

  } catch (error) {
    console.error('❌ Error deleting meal:', error);
    res.status(500).json({ error: 'Server error deleting meal.' });
  }
});


// 

// CAMBIAR PASSWORD -----------FDFDFFDFJHDSIOFNIOUD

//

// En tu backend index.ts

app.put('/patients/change-password', async (req: Request, res: Response) => {
  const { patient_id, currentPassword, newPassword } = req.body;

  if (!patient_id || !currentPassword || !newPassword) {
    return res.status(400).json({ message: 'Todos los campos son obligatorios.' });
  }

  try {
    // ✅ Volvemos a usar findById, que ahora funcionará correctamente
    const patient = await Patient.findById(patient_id).select('+password');

    if (!patient) {
      return res.status(404).json({ message: 'Usuario no encontrado.' });
    }

    const isMatch = await bcrypt.compare(currentPassword, patient.password);
    if (!isMatch) {
      return res.status(401).json({ message: 'La contraseña actual es incorrecta.' });
    }

    const salt = await bcrypt.genSalt(10);
    patient.password = await bcrypt.hash(newPassword, salt);
    await patient.save();

    res.json({ message: 'Contraseña actualizada con éxito.' });

  } catch (error) {
    console.error('❌ Error al cambiar la contraseña:', error);
    res.status(500).json({ error: 'Error interno del servidor.' });
  }
});