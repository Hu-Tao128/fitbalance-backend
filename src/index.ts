import axios from "axios";
import cors from 'cors';
import crypto from 'crypto';
import dotenv from 'dotenv';
import express, { Request, Response } from 'express';
import mongoose from 'mongoose';
import OAuth from 'oauth-1.0a';

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
const MONGODB_URI = getEnv('MONGODB_URI') || "mongodb+srv://oscarblaugrana:dcBVGQu9dgoWjt9K@fitbalance.4vcdip8.mongodb.net/fitbalance";
const FATSECRET_CONSUMER_KEY = getEnv('FATSECRET_CONSUMER_KEY') || "e0ef09f06dcb4f04bc16a41dfeb7e971";
const FATSECRET_CONSUMER_SECRET = getEnv('FATSECRET_CONSUMER_SECRET') || "040d3b31c2704f07a156a5bdcf2f059f";
const NUTRITIONIX_APP_ID = getEnv('NUTRITIONIX_APP_ID') || "9cb9997e";
const NUTRITIONIX_APP_KEY = getEnv('NUTRITIONIX_APP_KEY') || "f20dd733aa2b7930250a27e9c8e5e167";

// Configuración de OAuth para FatSecret
const fatSecretOAuth = new OAuth({
  consumer: {
    key: FATSECRET_CONSUMER_KEY,
    secret: FATSECRET_CONSUMER_SECRET
  },
  signature_method: 'HMAC-SHA1',
  hash_function: (baseString: string, key: string) => {
    return crypto.createHmac('sha1', key).update(baseString).digest('base64');
  }
});

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

// 🔌 Conexión a MongoDB
mongoose.connect(MONGODB_URI)
  .then(() => console.log('✅ Conectado a MongoDB Atlas'))
  .catch((err) => {
    console.error('❌ Error al conectar a MongoDB:', err);
    process.exit(1);
  });

// 🔎 Función para buscar en FatSecret
async function searchFatSecretByText(query: string) {
  const url = 'https://platform.fatsecret.com/rest/server.api';
  const method = 'POST';
  const data = {
    method: 'foods.search',
    search_expression: query,
    format: 'json',
    max_results: '10'
  };

  const requestData = { url, method, data };
  const headers = {
    ...fatSecretOAuth.toHeader(fatSecretOAuth.authorize(requestData)),
    'Content-Type': 'application/x-www-form-urlencoded'
  };

  const response = await axios.post(url, new URLSearchParams(data), { headers });
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
    const usuarios = await Patient.find();
    res.json(usuarios);
  } catch (err) {
    res.status(500).json({ error: 'Error al obtener usuarios' });
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
    res.status(500).json({ error: 'Error al obtener alimentos' });
  }
});

// 🚀 Arranque del servidor
app.listen(PORT, () => {
  console.log(`🚀 Servidor corriendo en http://localhost:${PORT}`);
});
