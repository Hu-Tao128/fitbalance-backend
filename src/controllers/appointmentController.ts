import { Request, Response } from 'express';
import { Types } from 'mongoose';
import { Appointment } from '../models';

export async function getPatientAppointments(req: Request, res: Response): Promise<void> {
  const { patient_id } = req.params;

  console.log(`Backend: Buscando citas para el patient_id: ${patient_id}`);

  if (!Types.ObjectId.isValid(patient_id)) {
    console.log('Backend: El ID recibido no es valido.');
    res.status(400).json({ error: 'ID de paciente no valido' });
    return;
  }

  try {
    const appointments = await Appointment.find({ patient_id: new Types.ObjectId(patient_id) });

    console.log(`Backend: Se encontraron ${appointments.length} citas.`);

    res.status(200).json(appointments);
  } catch (error) {
    console.error('Backend: Error en /appointments/:patient_id:', error);
    res.status(500).json({ error: 'Error al obtener las citas' });
  }
}
