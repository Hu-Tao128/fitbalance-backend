import 'dotenv/config';
import mongoose from 'mongoose';
import { createApp } from './app';
import { MONGODB_URI, PORT } from './config/env';

const app = createApp();

mongoose
  .connect(MONGODB_URI)
  .then(() => {
    console.log('Conectado a MongoDB Atlas');
    app.listen(PORT, () => {
      console.log(`Servidor corriendo en http://localhost:${PORT}`);
    });
  })
  .catch((err) => {
    console.error('Error al conectar a MongoDB:', err);
    process.exit(1);
  });
