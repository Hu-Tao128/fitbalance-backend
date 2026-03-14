import mongoose, { Document, Schema, Types } from 'mongoose';

export interface IAppointment extends Document {
  nutritionist_id: Types.ObjectId;
  patient_id: Types.ObjectId;
  appointment_date: Date;
  appointment_time: string;
  appointment_type?: string;
  status: 'scheduled' | 'completed' | 'cancelled';
  notes?: string;
}

const AppointmentSchema = new Schema<IAppointment>(
  {
    nutritionist_id: { type: Schema.Types.ObjectId, required: true, ref: 'Nutritionist' },
    patient_id: { type: Schema.Types.ObjectId, required: true, ref: 'Patient' },
    appointment_date: { type: Date, required: true },
    appointment_time: { type: String, required: true },
    appointment_type: { type: String },
    status: { type: String, enum: ['scheduled', 'completed', 'cancelled'], required: true },
    notes: { type: String },
  },
  {
    collection: 'Appointments',
    timestamps: { createdAt: 'created_at', updatedAt: 'updated_at' },
  }
);

export const Appointment = mongoose.model<IAppointment>('Appointment', AppointmentSchema);
