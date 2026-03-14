import {
  nowInTijuana,
  todayStartInTijuana,
  todayEndInTijuana,
  getTodayWeekday,
  parseISODateInTijuana,
} from '../services/dateService';

describe('dateService', () => {
  describe('nowInTijuana', () => {
    it('should return a DateTime in America/Tijuana timezone', () => {
      const result = nowInTijuana();
      expect(result.zoneName).toBe('America/Tijuana');
    });
  });

  describe('todayStartInTijuana', () => {
    it('should return a Date at midnight in Tijuana timezone', () => {
      const result = todayStartInTijuana();
      expect(result.getHours()).toBe(0);
      expect(result.getMinutes()).toBe(0);
      expect(result.getSeconds()).toBe(0);
      expect(result.getMilliseconds()).toBe(0);
    });

    it('should return a valid Date object', () => {
      const result = todayStartInTijuana();
      expect(result).toBeInstanceOf(Date);
    });
  });

  describe('todayEndInTijuana', () => {
    it('should return a Date at end of day in Tijuana timezone', () => {
      const result = todayEndInTijuana();
      expect(result.getHours()).toBe(23);
      expect(result.getMinutes()).toBe(59);
      expect(result.getSeconds()).toBe(59);
      expect(result.getMilliseconds()).toBe(999);
    });
  });

  describe('getTodayWeekday', () => {
    it('should return a valid weekday string', () => {
      const result = getTodayWeekday();
      expect(typeof result).toBe('string');
      expect(result.length).toBeGreaterThan(0);
    });
  });

  describe('parseISODateInTijuana', () => {
    it('should parse ISO date string and return start and end of day', () => {
      const result = parseISODateInTijuana('2024-06-15');

      expect(result.startOfDay).toBeInstanceOf(Date);
      expect(result.endOfDay).toBeInstanceOf(Date);
      expect(result.startOfDay.getHours()).toBe(0);
      expect(result.endOfDay.getHours()).toBe(23);
    });
  });
});
