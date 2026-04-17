import nodemailer from 'nodemailer';

const transporter = nodemailer.createTransport({
  service: process.env.EMAIL_SERVICE,
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
  },
});

export type EmailType = 'password_reset' | 'welcome' | 'reminder';

export interface EmailPayload {
  to: string;
  type: EmailType;
  data?: Record<string, unknown>;
}

function getStringValue(value: unknown, fallback: string): string {
  return typeof value === 'string' && value.trim() ? value : fallback;
}

const emailTemplates: Partial<Record<EmailType, (data: Record<string, unknown>) => string>> = {
  password_reset: (data) => {
    const name = getStringValue(data.name, 'usuario');
    const code = getStringValue(data.code, '------');

    return `
<div style="font-family: Arial, sans-serif; padding: 20px; color: #333;">
  <h2>Recuperacion de contrasena</h2>
  <p>Hola ${name}</p>
  <p>Tu codigo es:</p>
  <h1 style="letter-spacing: 5px;">${code}</h1>
  <p>Expira en 10 minutos.</p>
</div>
`;
  },
};

const subjectMap: Partial<Record<EmailType, string>> = {
  password_reset: 'Recuperacion de contrasena',
};

export async function sendEmail(payload: EmailPayload): Promise<void> {
  const { to, type, data = {} } = payload;
  const template = emailTemplates[type];
  const subject = subjectMap[type];
  if (!template || !subject) {
    throw new Error(`Tipo de email no configurado: ${type}`);
  }

  const html = template(data);
  const text =
    type === 'password_reset'
      ? `Tu codigo es: ${getStringValue(data.code, '------')}. Expira en 10 minutos.`
      : subject;

  const mailOptions = {
    from: process.env.EMAIL_USER,
    to,
    subject,
    text,
    html,
  };

  await transporter.sendMail(mailOptions);
}
