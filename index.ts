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

const PORT = process.env.PORT || 3000;
const MONGODB_URI = process.env.MONGODB_URI as string;

// Configuración de FatSecret
const FATSECRET_CONSUMER_KEY = process.env.FATSECRET_CONSUMER_KEY as string;
const FATSECRET_CONSUMER_SECRET = process.env.FATSECRET_CONSUMER_SECRET as string;

if (!MONGODB_URI) {
  throw new Error('No se encontró MONGODB_URI en el archivo .env');
}

if (!FATSECRET_CONSUMER_KEY || !FATSECRET_CONSUMER_SECRET) {
  console.warn('FatSecret API keys no encontradas');
}

const fatSecretOAuth = new OAuth({
  consumer: {
    key: FATSECRET_CONSUMER_KEY,
    secret: FATSECRET_CONSUMER_SECRET
  },
  signature_method: 'HMAC-SHA1',
  hash_function: (baseString: string, key: string) => {
    return crypto
      .createHmac('sha1', key)
      .update(baseString)
      .digest('base64');
  }
});

// Esquema y modelo para pacientes
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

// Conexión a MongoDB
mongoose.connect(MONGODB_URI)
  .then(() => console.log('✅ Conectado a MongoDB Atlas'))
  .catch((err) => console.error('❌ Error al conectar a MongoDB:', err));

// Fatsecret
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

// Ruta de búsqueda por lenguaje natural usando Nutritionix y FatSecret
app.post('/search-food', async (req: Request, res: Response) => {
  const { query } = req.body;

  if (!query) {
    return res.status(400).json({ error: 'Falta el parámetro "query"' });
  }

  try {
    // 1. Buscar en Nutritionix
    const nutritionixResponse = await axios.post(
        'https://trackapi.nutritionix.com/v2/natural/nutrients',
        { query },
        {
          headers: {
            'x-app-id': process.env.NUTRITIONIX_APP_ID!,
            'x-app-key': process.env.NUTRITIONIX_APP_KEY!,
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

    // 2. Si no hay resultados, buscar en FatSecret
    const fatSecretData = await searchFatSecretByText(query);
    const foods = fatSecretData?.foods?.food;

    if (foods && foods.length > 0) {
      return res.json({
        source: 'fatsecret',
        results: foods
      });
    }

    // 3. Si ninguna API devuelve resultados
    return res.status(404).json({ message: 'No se encontraron alimentos con ese nombre.' });

  } catch (error: any) {
    console.error('Error en /search-food:', error.message);
    return res.status(500).json({ error: 'Error en la búsqueda de alimentos' });
  }
});

// Rutas
app.get('/usuarios', async (req: Request, res: Response) => {
  try {
    const usuarios = await Patient.find();
    res.json(usuarios);
  } catch (err) {
    console.error('❌ Error al obtener usuarios:', err);
    res.status(500).json({ error: 'Error al obtener usuarios' });
  }
});

app.post('/usuarios', async (req: Request, res: Response) => {
  try {
    const nuevoUsuario = new Patient(req.body);
    await nuevoUsuario.save();
    res.status(201).json(nuevoUsuario);
  } catch (err) {
    console.error('❌ Error al guardar usuario:', err);
    res.status(500).json({ error: 'Error al guardar usuario' });
  }
});

app.post('/login', async (req: Request, res: Response): Promise<void> => {
  const { usuario, password } = req.body;

  console.log('📥 Datos recibidos en /login:', { usuario, password });

  if (!usuario || !password) {
    res.status(400).json({ mensaje: 'Faltan campos: usuario y/o contraseña' });
    return;
  }

  try {
    const paciente = await Patient.findOne({ usuario, password }).select('-password');

    if (!paciente) {
      console.log('❌ No se encontró paciente con esas credenciales');
      res.status(401).json({ mensaje: 'Credenciales incorrectas' });
      return;
    }

    console.log('✅ Login exitoso para:', paciente.usuario);
    res.json({
      mensaje: 'Inicio de sesión exitoso',
      id: paciente._id,
      usuario: paciente.usuario,
      nombre: paciente.nombre,
      correo: paciente.correo || paciente.email
    });
  } catch (err) {
    console.error('❌ Error al iniciar sesión:', err);
    res.status(500).json({ error: 'Error del servidor' });
  }
});

// Obtener detalles de un usuario específico por su nombre de usuario
app.get('/user/:usuario', async (req: Request, res: Response) => {
  const { usuario } = req.params;

  try {
    const paciente = await Patient.findOne({ usuario }).select('-password'); // Nunca mandes la password

    if (!paciente) {
      return res.status(404).json({ mensaje: 'Usuario no encontrado' });
    }

    res.json(paciente);
  } catch (err) {
    console.error('❌ Error al obtener datos del usuario:', err);
    res.status(500).json({ error: 'Error al obtener los datos del usuario' });
  }
});

app.listen(PORT, () => {
  console.log(`🚀 Servidor corriendo en http://localhost:${PORT}`);
});


//-----------------------FOOD------------------------

// ✅ Agrega este modelo en tu backend (en el mismo archivo o modularizado)
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

app.get('/api/food', async (req, res) => {
  try {
    const foods = await Food.find();
    res.json(foods);
  } catch (err) {
    console.error('❌ Error al obtener alimentos:', err);
    res.status(500).json({ error: 'Error al obtener alimentos' });
  }
});

