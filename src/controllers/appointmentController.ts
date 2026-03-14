import { Request, Response } from 'express';
import { Types } from 'mongoose';
import { Appointment } from '../models';

export async function getPatientAppointments(req: Request, res: Response): Promise<void> {
  const { patient_id } = req.params;

  if (!Types.ObjectId.isValid(patient_id)) {
    res.status(400).json({ error: 'ID de paciente no valido' });
    return;
  }

  try {
    const appointments = await Appointment.find({ patient_id: new Types.ObjectId(patient_id) });
    res.status(200).json(appointments);
  } catch (error) {
    console.error('Error fetching appointments:', error);
    res.status(500).json({ error: 'Error al obtener las citas' });
  }
}
