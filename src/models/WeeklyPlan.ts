import mongoose, { Document, Schema, Types } from 'mongoose';

export interface IWeeklyPlanFood {
  food_id: string;
  grams: number;
}

export interface IWeeklyMeal {
  day: 'monday' | 'tuesday' | 'wednesday' | 'thursday' | 'friday' | 'saturday' | 'sunday';
  type: 'breakfast' | 'lunch' | 'dinner' | 'snack';
  time: string;
  foods: IWeeklyPlanFood[];
}

export interface IWeeklyPlan extends Document {
  patient_id: Types.ObjectId;
  week_start: Date;
  dailyCalories: number;
  protein: number;
  fat: number;
  carbs: number;
  meals: IWeeklyMeal[];
}

const FoodSubSchema = new Schema<IWeeklyPlanFood>(
  {
    food_id: { type: String, required: true },
    grams: { type: Number, required: true, min: 1 },
  },
  { _id: false }
);

const MealSchema = new Schema<IWeeklyMeal>(
  {
    day: {
      type: String,
      enum: ['monday', 'tuesday', 'wednesday', 'thursday', 'friday', 'saturday', 'sunday'],
      required: true,
    },
    type: {
      type: String,
      enum: ['breakfast', 'lunch', 'dinner', 'snack'],
      required: true,
    },
    time: { type: String, required: true },
    foods: { type: [FoodSubSchema], required: true },
  },
  { _id: false }
);

const WeeklyPlanSchema = new Schema<IWeeklyPlan>(
  {
    patient_id: { type: Schema.Types.ObjectId, required: true, ref: 'Patient' },
    week_start: { type: Date, required: true },
    dailyCalories: { type: Number, required: true },
    protein: { type: Number, required: true },
    fat: { type: Number, required: true },
    carbs: { type: Number, required: true },
    meals: { type: [MealSchema], required: true },
  },
  {
    collection: 'WeeklyPlan',
    timestamps: true,
  }
);

export const WeeklyPlan = mongoose.model<IWeeklyPlan>('WeeklyPlan', WeeklyPlanSchema);
