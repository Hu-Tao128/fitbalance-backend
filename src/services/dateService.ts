import { DateTime } from 'luxon';

const TIMEZONE = 'America/Tijuana';

export function nowInTijuana(): DateTime {
  return DateTime.now().setZone(TIMEZONE);
}

export function todayStartInTijuana(): Date {
  return nowInTijuana().startOf('day').toJSDate();
}

export function todayEndInTijuana(): Date {
  return nowInTijuana().endOf('day').toJSDate();
}

export function getTodayWeekday(): string {
  return nowInTijuana().weekdayLong!.toLowerCase();
}

export function parseISODateInTijuana(dateString: string): { startOfDay: Date; endOfDay: Date } {
  const dt = DateTime.fromISO(dateString, { zone: TIMEZONE });
  return {
    startOfDay: dt.startOf('day').toJSDate(),
    endOfDay: dt.endOf('day').toJSDate(),
  };
}

export function formatDateToISO(date: Date): string {
  return DateTime.fromJSDate(date).setZone(TIMEZONE).toISODate() || '';
}
