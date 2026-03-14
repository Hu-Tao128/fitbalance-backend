import nodemailer from 'nodemailer';
import { getEnv } from '../config/env';

const transporter = nodemailer.createTransport({
  service: process.env.EMAIL_SERVICE,
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
  },
});

export interface SendEmailOptions {
  to: string;
  subject: string;
  text: string;
  html?: string;
}

export async function sendEmail(options: SendEmailOptions): Promise<void> {
  const mailOptions = {
    from: process.env.EMAIL_USER,
    to: options.to,
    subject: options.subject,
    text: options.text,
    html: options.html,
  };

  await transporter.sendMail(mailOptions);
}

export async function sendPasswordResetEmail(
  email: string,
  name: string,
  token: string
): Promise<void> {
  await sendEmail({
    to: email,
    subject: 'Codigo de recuperacion - Nutifrut',
    text: `Hola ${name},\n\nTu codigo de recuperacion es: ${token}\nEste codigo expira en 1 hora.\n\nAtentamente,\nEl equipo de Nutifrut.`,
  });
}
