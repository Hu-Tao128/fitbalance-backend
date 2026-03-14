import mongoose, { Document, Schema, Types } from 'mongoose';

export interface IMealFood {
  food_id: Types.ObjectId;
  grams: number;
  nutrients?: {
    calories?: number;
    protein?: number;
    fat?: number;
    carbs?: number;
  };
}

export interface IMeal {
  _id?: Types.ObjectId;
  day: string;
  type: 'breakfast' | 'lunch' | 'dinner' | 'snack';
  time: string;
  foods: IMealFood[];
  consumed?: boolean;
  notes?: string;
}

export interface IDailyMealLog extends Document {
  patient_id: Types.ObjectId;
  date: Date;
  totalCalories?: number;
  totalProtein?: number;
  totalFat?: number;
  totalCarbs?: number;
  caloriesConsumed?: number;
  meals: IMeal[];
  notes?: string;
}

const MealFoodSchema = new Schema<IMealFood>(
  {
    food_id: { type: Schema.Types.ObjectId, required: true, ref: 'Food' },
    grams: { type: Number, required: true, min: 1 },
    nutrients: {
      calories: { type: Number, min: 0 },
      protein: { type: Number, min: 0 },
      fat: { type: Number, min: 0 },
      carbs: { type: Number, min: 0 },
    },
  },
  { _id: false }
);

const MealSubSchema = new Schema<IMeal>(
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
    foods: {
      type: [MealFoodSchema],
      required: true,
    },
    consumed: { type: Boolean, default: false },
    notes: { type: String },
  },
  { _id: true }
);

const DailyMealLogSchema = new Schema<IDailyMealLog>(
  {
    patient_id: { type: Schema.Types.ObjectId, required: true, ref: 'Patient' },
    date: { type: Date, required: true, index: true },
    totalCalories: { type: Number, min: 0 },
    totalProtein: { type: Number, min: 0 },
    totalFat: { type: Number, min: 0 },
    totalCarbs: { type: Number, min: 0 },
    caloriesConsumed: { type: Number, min: 0 },
    meals: {
      type: [MealSubSchema],
      default: [],
    },
    notes: { type: String },
  },
  {
    collection: 'DailyMealLogs',
    timestamps: true,
  }
);

export const DailyMealLog = mongoose.model<IDailyMealLog>('DailyMealLog', DailyMealLogSchema);
