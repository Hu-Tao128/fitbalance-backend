import { Request, Response } from 'express';
import bcrypt from 'bcryptjs';
import crypto from 'crypto';
import { Types } from 'mongoose';
import { Patient, PasswordResetToken } from '../models';
import { sendPasswordResetEmail } from '../services/emailService';
import { SALT_ROUNDS } from '../config/env';
import { generateToken } from '../utils/jwt';

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
    const patient = await Patient.findOne({ email });

    if (!patient) {
      res.status(404).json({ message: 'No se encontro un paciente con ese correo.' });
      return;
    }

    const token = crypto.randomBytes(3).toString('hex');

    const resetToken = new PasswordResetToken({
      patient_id: patient._id,
      token,
      expiresAt: new Date(Date.now() + 60 * 60 * 1000),
    });

    await resetToken.save();

    await sendPasswordResetEmail(email, patient.name, token);

    res.json({ message: 'Codigo de recuperacion enviado al correo del paciente.' });
  } catch (error) {
    console.error('Error al enviar el codigo de recuperacion:', error);
    res.status(500).json({ error: 'Error al enviar el correo de recuperacion.' });
  }
}

export async function changePassword(req: Request, res: Response): Promise<void> {
  const { patient_id, currentPassword, newPassword } = req.body;

  if (!patient_id || !currentPassword || !newPassword) {
    res.status(400).json({ message: 'Todos los campos son obligatorios.' });
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
