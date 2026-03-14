import mongoose, { Document, Schema, Types } from 'mongoose';

export interface IPatientMealIngredient {
  food_id: Types.ObjectId;
  amount_g: number;
}

export interface IPatientMeal extends Document {
  patient_id: Types.ObjectId;
  name: string;
  ingredients: IPatientMealIngredient[];
  nutrients: {
    energy_kcal: number;
    protein_g: number;
    carbohydrates_g: number;
    fat_g: number;
    fiber_g: number;
    sugar_g: number;
  };
  instructions?: string;
  created_at: Date;
  updated_at: Date;
}

const PatientMealIngredientSchema = new Schema<IPatientMealIngredient>({
  food_id: { type: Schema.Types.ObjectId, required: true, ref: 'Food' },
  amount_g: { type: Number, required: true, min: 1 },
});

const PatientMealSchema = new Schema<IPatientMeal>(
  {
    patient_id: { type: Schema.Types.ObjectId, required: true, ref: 'Patient' },
    name: { type: String, required: true },
    ingredients: [PatientMealIngredientSchema],
    nutrients: {
      energy_kcal: { type: Number, required: true, min: 0 },
      protein_g: { type: Number, required: true, min: 0 },
      carbohydrates_g: { type: Number, required: true, min: 0 },
      fat_g: { type: Number, required: true, min: 0 },
      fiber_g: { type: Number, required: true, min: 0 },
      sugar_g: { type: Number, required: true, min: 0 },
    },
    instructions: { type: String },
    created_at: { type: Date, default: Date.now },
    updated_at: { type: Date, default: Date.now },
  },
  {
    collection: 'PatientMeals',
    timestamps: { createdAt: 'created_at', updatedAt: 'updated_at' },
  }
);

export const PatientMeal = mongoose.model<IPatientMeal>('PatientMeal', PatientMealSchema);
