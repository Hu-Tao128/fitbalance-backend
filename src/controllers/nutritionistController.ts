import { Request, Response } from 'express';
import { Types } from 'mongoose';
import { Nutritionist } from '../models';

export async function getNutritionist(req: Request, res: Response): Promise<void> {
  const { id } = req.params;

  if (!Types.ObjectId.isValid(id)) {
    res.status(400).json({ error: 'Invalid nutritionist ID' });
    return;
  }

  try {
    const nutritionist = await Nutritionist.findById(id).select('-password');

    if (!nutritionist) {
      res.status(404).json({ message: 'Nutritionist not found in DB.' });
      return;
    }

    res.json(nutritionist);
  } catch (error) {
    console.error('Error fetching nutritionist:', error);
    res.status(500).json({ error: 'Internal server error while fetching nutritionist.' });
  }
}
