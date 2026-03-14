import mongoose, { Document, Schema } from 'mongoose';

export interface IFood extends Document {
  name: string;
  portion_size_g: number;
  nutrients: {
    energy_kj: number;
    energy_kcal: number;
    fat_g: number;
    saturated_fat_g: number;
    monounsaturated_fat_g: number;
    polyunsaturated_fat_g: number;
    carbohydrates_g: number;
    sugar_g: number;
    fiber_g: number;
    protein_g: number;
    salt_g: number;
    cholesterol_mg: number;
    potassium_mg: number;
  };
  percent_RI?: any;
  category?: string;
}

const FoodSchema = new Schema<IFood>({}, { strict: false, collection: 'Food' });

export const Food = mongoose.model<IFood>('Food', FoodSchema);
