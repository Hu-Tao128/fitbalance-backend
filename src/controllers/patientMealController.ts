import { Request, Response } from 'express';
import { Types } from 'mongoose';
import { PatientMeal } from '../models';

export async function createPatientMeal(req: Request, res: Response): Promise<void> {
  const { patient_id, name, ingredients, nutrients, instructions } = req.body;

  if (!patient_id || !name || !ingredients || ingredients.length === 0 || !nutrients) {
    res
      .status(400)
      .json({ error: 'Faltan campos obligatorios o la lista de ingredientes esta vacia.' });
    return;
  }

  if (!Types.ObjectId.isValid(patient_id)) {
    res.status(400).json({ error: 'ID de paciente no valido.' });
    return;
  }

  try {
    const newMeal = new PatientMeal({
      patient_id: new Types.ObjectId(patient_id),
      name,
      ingredients: ingredients.map((ing: any) => ({
        food_id: new Types.ObjectId(ing.food_id),
        amount_g: ing.amount_g,
      })),
      nutrients,
      instructions,
    });

    await newMeal.save();
    res.status(201).json({ message: 'Comida personalizada creada con exito', meal: newMeal });
  } catch (error) {
    console.error('Error al crear comida personalizada:', error);
    res.status(500).json({ error: 'Error interno del servidor al crear comida.' });
  }
}

export async function getPatientMeals(req: Request, res: Response): Promise<void> {
  const { patient_id } = req.params;

  if (!Types.ObjectId.isValid(patient_id)) {
    res.status(400).json({ error: 'ID de paciente no valido.' });
    return;
  }

  try {
    const meals = await PatientMeal.find({ patient_id: new Types.ObjectId(patient_id) }).populate(
      'ingredients.food_id',
      'name portion_size_g nutrients'
    );

    res.json(meals);
  } catch (error) {
    console.error('Error al obtener comidas personalizadas:', error);
    res.status(500).json({ error: 'Error interno del servidor al obtener comidas.' });
  }
}

export async function updatePatientMeal(req: Request, res: Response): Promise<void> {
  const { meal_id } = req.params;
  const { name, ingredients, nutrients, instructions } = req.body;

  if (!Types.ObjectId.isValid(meal_id)) {
    res.status(400).json({ error: 'ID de comida no valido.' });
    return;
  }

  if (!name || !ingredients || ingredients.length === 0 || !nutrients) {
    res
      .status(400)
      .json({ error: 'Faltan campos obligatorios o la lista de ingredientes esta vacia.' });
    return;
  }

  try {
    const updatedMeal = await PatientMeal.findByIdAndUpdate(
      meal_id,
      {
        name,
        ingredients: ingredients.map((ing: any) => ({
          food_id: new Types.ObjectId(ing.food_id),
          amount_g: ing.amount_g,
        })),
        nutrients,
        instructions,
        updated_at: new Date(),
      },
      { new: true }
    );

    if (!updatedMeal) {
      res.status(404).json({ message: 'Comida personalizada no encontrada.' });
      return;
    }

    res.json({ message: 'Comida personalizada actualizada con exito', meal: updatedMeal });
  } catch (error) {
    console.error('Error al actualizar comida personalizada:', error);
    res.status(500).json({ error: 'Error interno del servidor al actualizar comida.' });
  }
}

export async function deletePatientMeal(req: Request, res: Response): Promise<void> {
  const { meal_id } = req.params;

  if (!Types.ObjectId.isValid(meal_id)) {
    res.status(400).json({ error: 'ID de comida no valido.' });
    return;
  }

  try {
    const deletedMeal = await PatientMeal.findByIdAndDelete(meal_id);

    if (!deletedMeal) {
      res.status(404).json({ message: 'Comida personalizada no encontrada.' });
      return;
    }

    res.json({ message: 'Comida personalizada eliminada con exito.' });
  } catch (error) {
    console.error('Error al eliminar comida personalizada:', error);
    res.status(500).json({ error: 'Error interno del servidor al eliminar comida.' });
  }
}
