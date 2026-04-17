import { Request, Response } from 'express';
import bcrypt from 'bcryptjs';
import { randomInt } from 'crypto';
import { Patient } from '../models';
import { sendEmail } from '../services/emailService';
import { SALT_ROUNDS } from '../config/env';
import { generateToken, verifyToken } from '../utils/jwt';

const RESET_CODE_TTL_MS = 10 * 60 * 1000;
const RESET_REQUEST_INTERVAL_MS = 60 * 1000;

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
    const patient = await Patient.findOne({ email }).select(
      '+resetCode +resetCodeExpires +lastResetRequest'
    );

    if (!patient) {
      res.json({ message: 'Codigo de recuperacion enviado al correo del paciente.' });
      return;
    }

    if (
      patient.lastResetRequest &&
      Date.now() - new Date(patient.lastResetRequest).getTime() < RESET_REQUEST_INTERVAL_MS
    ) {
      res.status(429).json({ message: 'Espera antes de solicitar otro codigo.' });
      return;
    }

    // Invalidar explicitamente cualquier codigo previo antes de emitir uno nuevo.
    patient.resetCode = null;
    patient.resetCodeExpires = null;
    await patient.save();

    const code = randomInt(0, 1000000).toString().padStart(6, '0');
    const hashedCode = await bcrypt.hash(code, SALT_ROUNDS);

    patient.resetCode = hashedCode;
    patient.resetCodeExpires = new Date(Date.now() + RESET_CODE_TTL_MS);
    patient.lastResetRequest = new Date();
    await patient.save();

    await sendEmail({
      to: email,
      type: 'password_reset',
      data: {
        name: patient.name,
        code,
      },
    });

    res.json({ message: 'Codigo de recuperacion enviado al correo del paciente.' });
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
    const patient = await Patient.findOne({ email }).select('+resetCode +resetCodeExpires');

    if (!patient) {
      res.status(404).json({ message: 'Usuario no encontrado.' });
      return;
    }

    if (!patient.resetCode) {
      res.status(400).json({ message: 'Codigo invalido.' });
      return;
    }

    const isValidCode = await bcrypt.compare(code, patient.resetCode);
    if (!isValidCode) {
      res.status(400).json({ message: 'Codigo invalido.' });
      return;
    }

    if (!patient.resetCodeExpires || patient.resetCodeExpires < new Date()) {
      res.status(400).json({ message: 'Codigo expirado.' });
      return;
    }

    patient.resetCode = null;
    patient.resetCodeExpires = null;
    await patient.save();

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
    patient.password = await bcrypt.hash(newPassword, salt);
    await patient.save();

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
    patient.password = await bcrypt.hash(newPassword, salt);
    await patient.save();

    res.json({ message: 'Contrasena actualizada con exito.' });
  } catch (error) {
    console.error('Error al cambiar la contrasena:', error);
    res.status(500).json({ error: 'Error interno del servidor.' });
  }
}
