import { Request, Response } from 'express';
import bcrypt from 'bcryptjs';
import { randomInt } from 'crypto';
import { PasswordResetToken, Patient } from '../models';
import { sendEmail } from '../services/emailService';
import { SALT_ROUNDS } from '../config/env';
import { generateToken, verifyToken } from '../utils/jwt';

const RESET_CODE_TTL_MS = 10 * 60 * 1000;
const RESET_REQUEST_INTERVAL_MS = 60 * 1000;

function maskEmail(email: string): string {
  const [local, domain] = email.split('@');
  if (!local || !domain) return email;
  if (local.length <= 2) return `**@${domain}`;
  return `${local.slice(0, 2)}***@${domain}`;
}

function validatePassword(newPassword: string): string | null {
  if (newPassword.length < 6) {
    return 'La contrasena debe tener al menos 6 caracteres.';
  }

  return null;
}

export async function login(req: Request, res: Response): Promise<void> {
  const { username, password } = req.body;

  if (!username || !password) {
    res.status(400).json({ message: 'Faltan campos: username y/o password' });
    return;
  }

  try {
    const patient = await Patient.findOne({ username }).select('+password');

    if (!patient) {
      res.status(401).json({ message: 'Credenciales invalidas' });
      return;
    }

    const isMatch = await bcrypt.compare(password, patient.password);

    if (!isMatch) {
      res.status(401).json({ message: 'Credenciales invalidas' });
      return;
    }

    const { password: _, ...patientData } = patient.toObject();

    // Generate JWT token
    const token = generateToken(
      {
        id: patient._id,
        username: patient.username,
        email: patient.email,
      },
      '24h'
    ); // Token expires in 24 hours

    res.json({
      message: 'Login exitoso',
      token,
      patient: patientData,
    });
  } catch (err) {
    console.error('Error en login:', err);
    res.status(500).json({ error: 'Error del servidor' });
  }
}

export async function sendResetCode(req: Request, res: Response): Promise<void> {
  const { email } = req.body;

  if (!email) {
    res.status(400).json({ message: 'El campo email es obligatorio.' });
    return;
  }

  try {
    console.info(`[auth] send-reset-code solicitado para ${maskEmail(email)}`);
    const patient = await Patient.findOne({ email });

    if (!patient) {
      console.info(`[auth] send-reset-code usuario no encontrado para ${maskEmail(email)}`);
      res.status(404).json({
        message: 'Usuario no encontrado.',
        userExists: false,
      });
      return;
    }

    const existingReset = await PasswordResetToken.findOne({ patient_id: patient._id });

    if (
      existingReset?.lastRequestAt &&
      Date.now() - new Date(existingReset.lastRequestAt).getTime() < RESET_REQUEST_INTERVAL_MS
    ) {
      console.info(`[auth] send-reset-code rate-limited para ${maskEmail(email)}`);
      res.status(429).json({ message: 'Espera antes de solicitar otro codigo.' });
      return;
    }

    // Generar nuevo código
    const code = randomInt(0, 1000000).toString().padStart(6, '0');
    const hashedCode = await bcrypt.hash(code, SALT_ROUNDS);

    await PasswordResetToken.findOneAndUpdate(
      { patient_id: patient._id },
      {
        token: hashedCode,
        expiresAt: new Date(Date.now() + RESET_CODE_TTL_MS),
        lastRequestAt: new Date(),
      },
      { upsert: true, new: true, setDefaultsOnInsert: true }
    );

    await sendEmail({
      to: email,
      type: 'password_reset',
      data: {
        name: patient.name,
        code,
      },
    });

    console.info(`[auth] send-reset-code enviado para ${maskEmail(email)}`);
    res.status(200).json({
      message: 'Codigo de recuperacion enviado al correo del paciente.',
      userExists: true,
    });
  } catch (error) {
    console.error('Error al enviar el codigo de recuperacion:', error);
    res.status(500).json({ error: 'Error al enviar el correo de recuperacion.' });
  }
}

export async function verifyResetCode(req: Request, res: Response): Promise<void> {
  const { email, code } = req.body;

  if (!email || !code) {
    res.status(400).json({ message: 'Los campos email y code son obligatorios.' });
    return;
  }

  try {
    const patient = await Patient.findOne({ email });

    if (!patient) {
      res.status(404).json({ message: 'Usuario no encontrado.' });
      return;
    }

    const resetTokenDoc = await PasswordResetToken.findOne({ patient_id: patient._id });

    if (!resetTokenDoc) {
      res.status(400).json({ message: 'Codigo invalido.' });
      return;
    }

    const isValidCode = await bcrypt.compare(code, resetTokenDoc.token);
    if (!isValidCode) {
      res.status(400).json({ message: 'Codigo invalido.' });
      return;
    }

    if (!resetTokenDoc.expiresAt || resetTokenDoc.expiresAt < new Date()) {
      await PasswordResetToken.deleteOne({ _id: resetTokenDoc._id });
      res.status(400).json({ message: 'Codigo expirado.' });
      return;
    }

    await PasswordResetToken.deleteOne({ _id: resetTokenDoc._id });

    const resetToken = generateToken(
      {
        id: patient._id.toString(),
        purpose: 'password-reset',
      },
      '10m'
    );

    res.json({ message: 'Codigo valido.', resetToken });
  } catch (error) {
    console.error('Error al verificar codigo de recuperacion:', error);
    res.status(500).json({ error: 'Error interno del servidor.' });
  }
}

export async function resetPassword(req: Request, res: Response): Promise<void> {
  const { token, newPassword } = req.body;

  if (!token || !newPassword) {
    res.status(400).json({ message: 'Los campos token y newPassword son obligatorios.' });
    return;
  }

  const passwordValidationError = validatePassword(newPassword);
  if (passwordValidationError) {
    res.status(400).json({ message: passwordValidationError });
    return;
  }

  try {
    const payload = verifyToken(token);

    if (!payload.id || payload.purpose !== 'password-reset') {
      res.status(401).json({ message: 'Token de recuperacion invalido.' });
      return;
    }

    const patient = await Patient.findById(payload.id).select('+password');

    if (!patient) {
      res.status(404).json({ message: 'Usuario no encontrado.' });
      return;
    }

    const salt = await bcrypt.genSalt(SALT_ROUNDS);
    const hashedPassword = await bcrypt.hash(newPassword, salt);

    await Patient.collection.updateOne(
      { _id: patient._id },
      { $set: { password: hashedPassword } },
      { bypassDocumentValidation: true }
    );

    res.json({ message: 'Contrasena actualizada con exito.' });
  } catch (error) {
    if (error instanceof Error && error.name === 'JsonWebTokenError') {
      res.status(401).json({ message: 'Token de recuperacion invalido.' });
      return;
    }

    if (error instanceof Error && error.name === 'TokenExpiredError') {
      res.status(401).json({ message: 'Token de recuperacion expirado.' });
      return;
    }

    console.error('Error al restablecer la contrasena:', error);
    res.status(500).json({ error: 'Error interno del servidor.' });
  }
}

export async function changePassword(req: Request, res: Response): Promise<void> {
  const { patient_id, currentPassword, newPassword } = req.body;

  if (!patient_id || !currentPassword || !newPassword) {
    res.status(400).json({ message: 'Todos los campos son obligatorios.' });
    return;
  }

  const passwordValidationError = validatePassword(newPassword);
  if (passwordValidationError) {
    res.status(400).json({ message: passwordValidationError });
    return;
  }

  try {
    const patient = await Patient.findById(patient_id).select('+password');

    if (!patient) {
      res.status(404).json({ message: 'Usuario no encontrado.' });
      return;
    }

    const isMatch = await bcrypt.compare(currentPassword, patient.password);
    if (!isMatch) {
      res.status(401).json({ message: 'La contrasena actual es incorrecta.' });
      return;
    }

    const salt = await bcrypt.genSalt(SALT_ROUNDS);
    const hashedPassword = await bcrypt.hash(newPassword, salt);

    await Patient.collection.updateOne(
      { _id: patient._id },
      { $set: { password: hashedPassword } },
      { bypassDocumentValidation: true }
    );

    res.json({ message: 'Contrasena actualizada con exito.' });
  } catch (error) {
    console.error('Error al cambiar la contrasena:', error);
    res.status(500).json({ error: 'Error interno del servidor.' });
  }
}
