import mongoose, { Document, Schema, Types } from 'mongoose';

export interface IPasswordResetToken extends Document {
  patient_id: Types.ObjectId;
  token: string;
  expiresAt: Date;
  lastRequestAt?: Date;
}

const PasswordResetTokenSchema = new Schema<IPasswordResetToken>(
  {
    patient_id: { type: Schema.Types.ObjectId, required: true, ref: 'Patient' },
    token: { type: String, required: true },
    expiresAt: { type: Date, required: true, default: () => new Date(Date.now() + 3600000) },
    lastRequestAt: { type: Date, default: null },
  },
  { collection: 'PasswordResetTokens' }
);

export const PasswordResetToken = mongoose.model<IPasswordResetToken>(
  'PasswordResetToken',
  PasswordResetTokenSchema
);
