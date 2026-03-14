import mongoose, { Document, Schema } from 'mongoose';

export interface INutritionist extends Document {
  name: string;
  lastName: string;
  secondLastName?: string;
  email: string;
  password?: string;
  city: string;
  street: string;
  neighborhood: string;
  streetNumber: string;
  licenseNumber?: string;
  specialization?: string;
  isActive: boolean;
}

const NutritionistSchema = new Schema<INutritionist>(
  {
    name: { type: String, required: true },
    lastName: { type: String, required: true },
    secondLastName: { type: String },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true, select: false },
    city: { type: String, required: true },
    street: { type: String, required: true },
    neighborhood: { type: String, required: true },
    streetNumber: { type: String, required: true },
    licenseNumber: { type: String },
    specialization: { type: String },
    isActive: { type: Boolean, default: true },
  },
  {
    collection: 'Nutritionist',
    timestamps: { createdAt: 'createdAt', updatedAt: 'updatedAt' },
  }
);

export const Nutritionist = mongoose.model<INutritionist>('Nutritionist', NutritionistSchema);
