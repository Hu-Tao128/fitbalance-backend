import express, { Application } from 'express';
import cors from 'cors';
import routes from './routes';

export function createApp(): Application {
  const app = express();

  app.use(cors());
  app.use(express.json());

  app.use(routes);

  return app;
}
