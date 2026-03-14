import { Request, Response } from 'express';
import { Types } from 'mongoose';
import { Patient } from '../models';

export async function getUserByUsername(req: Request, res: Response): Promise<void> {
  const { username } = req.params;

  try {
    const patient = await Patient.findOne({ username }).select('-password');

    if (!patient) {
      res.status(404).json({ message: 'Usuario no encontrado' });
      return;
    }

    res.json(patient);
  } catch (err) {
    res.status(500).json({ error: 'Error al obtener datos del usuario' });
  }
}

export async function updatePatient(req: Request, res: Response): Promise<void> {
  const { id } = req.params;
  const updateData = req.body;

  if (!Types.ObjectId.isValid(id)) {
    res.status(400).json({ error: 'ID de paciente no valido' });
    return;
  }

  delete updateData.username;
  delete updateData.password;

  try {
    const updatedPatient = await Patient.findByIdAndUpdate(
      id,
      { $set: updateData },
      { new: true, runValidators: true }
    ).select('-password');

    if (!updatedPatient) {
      res.status(404).json({ message: 'Paciente no encontrado' });
      return;
    }

    res.json({ message: 'Perfil actualizado con exito', patient: updatedPatient });
  } catch (error) {
    console.error('Error al actualizar el perfil:', error);
    res.status(500).json({ error: 'Error interno del servidor al actualizar el perfil' });
  }
}
