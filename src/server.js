import dotenv from 'dotenv';
import { createApp } from './app.js';
import { getPool } from './config/database.js';

dotenv.config();

const port = process.env.PORT || 3000;

async function start () {
  try {
    await getPool();
    const app = createApp();
    app.listen(port, () => {
      console.log(`ConexaShip API escuchando en puerto ${port}`);
    });
  } catch (error) {
    console.error('No se pudo iniciar el servidor', error);
    process.exit(1);
  }
}

start();
