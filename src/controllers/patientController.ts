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
  const id = req.params.id as string;
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

export async function saveFcmToken(req: Request, res: Response): Promise<void> {
  const userId = (req as any).user?.id;

  if (!userId) {
    res.status(401).json({ error: 'No autorizado' });
    return;
  }

  const { token } = req.body;

  if (!token) {
    res.status(400).json({ error: 'Token requerido' });
    return;
  }

  try {
    await Patient.findByIdAndUpdate(userId, {
      $addToSet: { fcmTokens: token },
    });

    res.json({ message: 'Token guardado correctamente' });
  } catch (error) {
    console.error('Error guardando FCM token:', error);
    res.status(500).json({ error: 'Error al guardar token' });
  }
}

export async function updateNotificationPreferences(
  req: Request,
  res: Response
): Promise<void> {
  const userId = (req as any).user?.id;
  const { planUpdates, appointments, reminders } = req.body;

  if (!userId) {
    res.status(401).json({ error: 'No autorizado' });
    return;
  }

  try {
    const updateData: Record<string, boolean> = {};
    if (typeof planUpdates === 'boolean') updateData['notificationPreferences.planUpdates'] = planUpdates;
    if (typeof appointments === 'boolean') updateData['notificationPreferences.appointments'] = appointments;
    if (typeof reminders === 'boolean') updateData['notificationPreferences.reminders'] = reminders;

    if (Object.keys(updateData).length === 0) {
      res.status(400).json({ error: 'Sin preferencias válidas para actualizar' });
      return;
    }

    await Patient.findByIdAndUpdate(userId, { $set: updateData });

    res.json({ message: 'Preferencias actualizadas' });
  } catch (error) {
    console.error('Error actualizando preferencias:', error);
    res.status(500).json({ error: 'Error al actualizar preferencias' });
  }
}
