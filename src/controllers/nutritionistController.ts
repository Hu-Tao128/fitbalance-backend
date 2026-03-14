import { Request, Response } from 'express';
import { Types } from 'mongoose';
import { Nutritionist } from '../models';

export async function getNutritionist(req: Request, res: Response): Promise<void> {
  const { id } = req.params;

  console.log('--- PETICION RECIBIDA EN /nutritionist/:id ---');
  console.log(`1. ID Recibido del request: ${id}`);

  if (!Types.ObjectId.isValid(id)) {
    console.log('2. El ID no es valido. Devolviendo error 400.');
    res.status(400).json({ error: 'Invalid nutritionist ID' });
    return;
  }

  try {
    console.log('2. El ID es valido. Buscando en la base de datos...');
    const nutritionist = await Nutritionist.findById(id).select('-password');

    console.log('3. Resultado de la busqueda:', nutritionist);

    if (!nutritionist) {
      console.log('4. Nutricionista no encontrado en la base de datos. Devolviendo error 404.');
      res.status(404).json({ message: 'Nutritionist not found in DB.' });
      return;
    }

    console.log('4. Nutricionista ENCONTRADO. Devolviendo datos.');
    res.json(nutritionist);
  } catch (error) {
    console.error('Error en el bloque try/catch:', error);
    res.status(500).json({ error: 'Internal server error while fetching nutritionist.' });
  }
}
