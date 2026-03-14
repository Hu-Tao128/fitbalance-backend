import {
  IPatient,
  IFood,
  IAppointment,
} from '../models';

describe('Models', () => {
  describe('IPatient', () => {
    it('should have required fields', () => {
      const patient: IPatient = {
        username: 'testuser',
        password: 'hashedpassword',
        name: 'Test User',
        email: 'test@example.com',
      } as IPatient;

      expect(patient.username).toBe('testuser');
      expect(patient.email).toBe('test@example.com');
    });

    it('should allow optional fields', () => {
      const patient: IPatient = {
        username: 'testuser',
        password: 'hashedpassword',
        name: 'Test User',
        email: 'test@example.com',
        phone: '+1234567890',
        age: 30,
        height_cm: 175,
        weight_kg: 70,
      } as IPatient;

      expect(patient.phone).toBe('+1234567890');
      expect(patient.age).toBe(30);
    });

    it('should allow gender enum values', () => {
      const patientMale: IPatient = {
        username: '',
        password: '',
        name: '',
        email: '',
        gender: 'male',
      } as IPatient;
      const patientFemale: IPatient = {
        username: '',
        password: '',
        name: '',
        email: '',
        gender: 'female',
      } as IPatient;
      const patientOther: IPatient = {
        username: '',
        password: '',
        name: '',
        email: '',
        gender: 'other',
      } as IPatient;

      expect(patientMale.gender).toBe('male');
      expect(patientFemale.gender).toBe('female');
      expect(patientOther.gender).toBe('other');
    });
  });

  describe('IFood', () => {
    it('should have nutrients structure', () => {
      const food: IFood = {
        name: 'Apple',
        portion_size_g: 100,
        nutrients: {
          energy_kj: 52,
          energy_kcal: 52,
          fat_g: 0.2,
          saturated_fat_g: 0,
          monounsaturated_fat_g: 0,
          polyunsaturated_fat_g: 0,
          carbohydrates_g: 14,
          sugar_g: 10,
          fiber_g: 2.4,
          protein_g: 0.3,
          salt_g: 0,
          cholesterol_mg: 0,
          potassium_mg: 107,
        },
      } as IFood;

      expect(food.nutrients.energy_kcal).toBe(52);
      expect(food.nutrients.protein_g).toBe(0.3);
    });
  });

  describe('IAppointment', () => {
    it('should allow valid status values', () => {
      const appointment: IAppointment = {
        nutritionist_id: 'nut123' as any,
        patient_id: 'pat123' as any,
        appointment_date: new Date(),
        appointment_time: '10:00',
        status: 'scheduled',
      } as IAppointment;

      expect(['scheduled', 'completed', 'cancelled']).toContain(appointment.status);
    });
  });
});
