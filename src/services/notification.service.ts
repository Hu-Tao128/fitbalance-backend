import admin from '../config/firebase';
import { IPatient } from '../models/Patient';

export const NOTIFICATION_TYPES = {
  PLAN_CREATED: 'PLAN_CREATED',
  PLAN_UPDATED: 'PLAN_UPDATED',
  PLAN_DELETED: 'PLAN_DELETED',
  APPOINTMENT_CREATED: 'APPOINTMENT_CREATED',
  APPOINTMENT_REMINDER: 'APPOINTMENT_REMINDER',
  APPOINTMENT_CANCELLED: 'APPOINTMENT_CANCELLED',
  APPOINTMENT_RESCHEDULED: 'APPOINTMENT_RESCHEDULED',
  DAILY_LOG_REMINDER: 'DAILY_LOG_REMINDER',
  STREAK_ACHIEVED: 'STREAK_ACHIEVED',
  GOAL_REACHED: 'GOAL_REACHED',
  SYSTEM_ALERT: 'SYSTEM_ALERT',
  WELCOME_MESSAGE: 'WELCOME_MESSAGE',
} as const;

export type NotificationType = (typeof NOTIFICATION_TYPES)[keyof typeof NOTIFICATION_TYPES];

export interface NotificationPayload {
  title: string;
  body: string;
  data?: Record<string, string>;
}

const notificationTemplates: Record<NotificationType, NotificationPayload> = {
  [NOTIFICATION_TYPES.PLAN_CREATED]: {
    title: 'Nuevo Plan Asignado 🥗',
    body: 'Tu nutriólogo te ha asignado un nuevo plan semanal. ¡échale un ojo!',
    data: { screen: 'PlanScreen' },
  },
  [NOTIFICATION_TYPES.PLAN_UPDATED]: {
    title: 'Plan Actualizado ✏️',
    body: 'Tu nutriólogo ha actualizado tu plan semanal. ¡Revísalo!',
    data: { screen: 'PlanScreen' },
  },
  [NOTIFICATION_TYPES.PLAN_DELETED]: {
    title: 'Plan Eliminado',
    body: 'Tu plan semanal ha sido eliminado.',
    data: { screen: 'PlanScreen' },
  },
  [NOTIFICATION_TYPES.APPOINTMENT_CREATED]: {
    title: 'Cita Agendada 📅',
    body: 'Tienes una nueva cita con tu nutriólogo. ¡Revisa los detalles!',
    data: { screen: 'Appointments' },
  },
  [NOTIFICATION_TYPES.APPOINTMENT_REMINDER]: {
    title: 'Recordatorio de Cita ⏰',
    body: 'Tienes una cita próxima con tu nutriólogo.',
    data: { screen: 'Appointments' },
  },
  [NOTIFICATION_TYPES.APPOINTMENT_CANCELLED]: {
    title: 'Cita Cancelada ❌',
    body: 'Tu cita ha sido cancelada. contacta a tu nutriólogo para reprogramar.',
    data: { screen: 'Appointments' },
  },
  [NOTIFICATION_TYPES.APPOINTMENT_RESCHEDULED]: {
    title: 'Cita Reprogramada 📅',
    body: 'Tu cita ha sido reprogramada. ¡Revisa los nuevos horarios!',
    data: { screen: 'Appointments' },
  },
  [NOTIFICATION_TYPES.DAILY_LOG_REMINDER]: {
    title: 'Recordatorio de Registro 📝',
    body: '¡No olvides registrar tus comidas de hoy!',
    data: { screen: 'DailyLog' },
  },
  [NOTIFICATION_TYPES.STREAK_ACHIEVED]: {
    title: '¡Racha Lograda! 🔥',
    body: '¡Felicidades! Has alcanzado una racha de alimentos registrados.',
    data: { screen: 'Profile' },
  },
  [NOTIFICATION_TYPES.GOAL_REACHED]: {
    title: '¡Meta Alcanzada! 🎉',
    body: '¡Felicidades! Has alcanzado tu objetivo.',
    data: { screen: 'Profile' },
  },
  [NOTIFICATION_TYPES.SYSTEM_ALERT]: {
    title: 'Alerta del Sistema ⚠️',
    body: 'Hay un mensaje importante para ti.',
    data: { screen: 'Home' },
  },
  [NOTIFICATION_TYPES.WELCOME_MESSAGE]: {
    title: '¡Bienvenido a FitBalance! 💪',
    body: 'Gracias por unirte. Tu viaje hacia una vida saludable comienza ahora.',
    data: { screen: 'Home' },
  },
};

export function buildNotification(type: NotificationType): NotificationPayload | null {
  return notificationTemplates[type] || null;
}

export function shouldSendNotification(
  patient: IPatient,
  type: NotificationType
): boolean {
  if (!patient.notificationPreferences) return true;

  const prefs = patient.notificationPreferences;

  switch (type) {
    case NOTIFICATION_TYPES.PLAN_CREATED:
    case NOTIFICATION_TYPES.PLAN_UPDATED:
    case NOTIFICATION_TYPES.PLAN_DELETED:
      return prefs.planUpdates;

    case NOTIFICATION_TYPES.APPOINTMENT_CREATED:
    case NOTIFICATION_TYPES.APPOINTMENT_REMINDER:
    case NOTIFICATION_TYPES.APPOINTMENT_CANCELLED:
    case NOTIFICATION_TYPES.APPOINTMENT_RESCHEDULED:
      return prefs.appointments;

    case NOTIFICATION_TYPES.DAILY_LOG_REMINDER:
    case NOTIFICATION_TYPES.STREAK_ACHIEVED:
    case NOTIFICATION_TYPES.GOAL_REACHED:
      return prefs.reminders;

    default:
      return true;
  }
}

export async function sendToUser(
  tokens: string[],
  payload: NotificationPayload
): Promise<{ successCount: number; failureCount: number }> {
  if (!tokens || tokens.length === 0) {
    return { successCount: 0, failureCount: 0 };
  }

  const message = {
    tokens,
    notification: {
      title: payload.title,
      body: payload.body,
    },
    data: payload.data || {},
  };

  try {
    const messaging = admin.messaging();
    const results = await Promise.all(
      tokens.map((token) =>
        messaging.send({
          token: token,
          notification: {
            title: payload.title,
            body: payload.body,
          },
          data: payload.data || {},
        })
      )
    );
    return {
      successCount: results.length,
      failureCount: 0,
    };
  } catch (error) {
    console.error('Error sending notification:', error);
    return { successCount: 0, failureCount: tokens.length };
  }
}