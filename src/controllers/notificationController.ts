import { Request, Response } from 'express';
import { Patient } from '../models';
import {
  NOTIFICATION_TYPES,
  NotificationType,
  buildNotification,
  sendToUser,
  shouldSendNotification,
} from '../services/notification.service';

export async function sendNotification(req: Request, res: Response): Promise<void> {
  const { userId, type } = req.body;

  if (!userId || !type) {
    res.status(400).json({ error: 'Faltan campos requeridos: userId, type' });
    return;
  }

  const validTypes = Object.values(NOTIFICATION_TYPES);
  if (!validTypes.includes(type as NotificationType)) {
    res.status(400).json({ error: 'Tipo de notificación inválido' });
    return;
  }

  try {
    const patient = await Patient.findById(userId).lean();

    if (!patient) {
      res.status(404).json({ error: 'Usuario no encontrado' });
      return;
    }

    if (!shouldSendNotification(patient as any, type as NotificationType)) {
      res.json({ message: 'Notificación bloqueada por preferencias del usuario' });
      return;
    }

    const tokens = patient.fcmTokens || [];
    if (tokens.length === 0) {
      res.status(404).json({ error: 'Usuario sin tokens FCM' });
      return;
    }

    const notification = buildNotification(type as NotificationType);
    if (!notification) {
      res.status(400).json({ error: 'Tipo no válido' });
      return;
    }

    const result = await sendToUser(tokens, notification);

    res.json({
      message: 'Notificación enviada',
      successCount: result.successCount,
      failureCount: result.failureCount,
    });
  } catch (error) {
    console.error('Error sending notification:', error);
    res.status(500).json({ error: 'Error interno del servidor' });
  }
}