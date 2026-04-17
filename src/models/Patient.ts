import mongoose, { Document, Schema } from 'mongoose';

export interface IPatient extends Document {
  username: string;
  password: string;
  name: string;
  email: string;
  phone?: string;
  age?: number;
  gender?: 'male' | 'female' | 'other';
  height_cm?: number;
  weight_kg?: number;
  objective?: string;
  allergies?: string[];
  dietary_restrictions?: string[];
  registration_date?: Date;
  notes?: string;
  last_consultation?: Date | null;
  nutritionist_id?: string;
  isActive?: boolean;
  resetCode?: string | null;
  resetCodeExpires?: Date | null;
  lastResetRequest?: Date | null;
}

const PatientSchema = new Schema<IPatient>(
  {
    username: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    name: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    phone: { type: String },
    age: { type: Number },
    gender: { type: String, enum: ['male', 'female', 'other'] },
    height_cm: { type: Number },
    weight_kg: { type: Number },
    objective: { type: String },
    allergies: { type: [String], default: [] },
    dietary_restrictions: { type: [String], default: [] },
    registration_date: { type: Date, default: Date.now },
    notes: { type: String, default: '' },
    last_consultation: { type: Date, default: null },
    nutritionist_id: { type: String },
    isActive: { type: Boolean, default: true },
    resetCode: { type: String, default: null, select: false },
    resetCodeExpires: { type: Date, default: null, select: false },
    lastResetRequest: { type: Date, default: null, select: false },
  },
  { collection: 'Patients' }
);

export const Patient = mongoose.model<IPatient>('Patient', PatientSchema);
