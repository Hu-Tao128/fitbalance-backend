import { Request, Response } from 'express';
import { Food } from '../models';
import { searchFoods } from '../services/nutritionixService';

export async function searchFood(req: Request, res: Response): Promise<void> {
  const { query } = req.body;

  if (!query) {
    res.status(400).json({ error: 'Falta el parametro "query"' });
    return;
  }

  try {
    const foodList = await searchFoods(query);

    if (foodList && foodList.length > 0) {
      res.json({
        source: 'nutritionix',
        results: foodList.slice(0, 3),
      });
      return;
    }

    res.status(404).json({ message: 'No se encontraron alimentos con ese nombre.' });
  } catch (error: any) {
    console.error('Error en /search-food:', error.message);
    res.status(500).json({ error: 'Error en la busqueda de alimentos' });
  }
}

export async function getAllFoods(req: Request, res: Response): Promise<void> {
  try {
    const foods = await Food.find();
    res.json(foods);
  } catch (err) {
    res.status(500).json({ error: 'Error al obtener alimentos' });
  }
}

export async function createOrUpdateFood(req: Request, res: Response): Promise<void> {
  const {
    food_name,
    serving_weight_grams,
    category,
    nf_calories,
    nf_protein,
    nf_total_carbohydrate,
    nf_total_fat,
    nf_dietary_fiber,
    nf_sugars,
  } = req.body;

  if (!food_name) {
    res.status(400).json({ error: 'El nombre del alimento es obligatorio.' });
    return;
  }

  try {
    const foodData = {
      name: food_name,
      portion_size_g: serving_weight_grams || 100,
      category: category || 'general',
      nutrients: {
        energy_kj: 0,
        energy_kcal: nf_calories || 0,
        fat_g: nf_total_fat || 0,
        saturated_fat_g: 0,
        monounsaturated_fat_g: 0,
        polyunsaturated_fat_g: 0,
        carbohydrates_g: nf_total_carbohydrate || 0,
        sugar_g: nf_sugars || 0,
        fiber_g: nf_dietary_fiber || 0,
        protein_g: nf_protein || 0,
        salt_g: 0,
        cholesterol_mg: 0,
        potassium_mg: 0,
      },
    };

    const savedFood = await Food.findOneAndUpdate(
      { name: foodData.name, portion_size_g: foodData.portion_size_g },
      { $set: foodData },
      { new: true, upsert: true, runValidators: true }
    );

    res.json(savedFood);
  } catch (err: any) {
    console.error('Error al guardar alimento:', err);
    res.status(500).json({ error: 'Error interno al guardar el alimento.', details: err.message });
  }
}
