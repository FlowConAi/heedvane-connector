// Primitive shape predicates for JSON that crossed a process boundary. This package
// hand-validates the connector wire contract by design: the contract has no TypeSpec
// schema (packages/protocol covers hub-to-engine boundaries), and both gateway and
// connector must reject malformed input without dependencies this package does not
// have. isRecord is local for the same reason the apps keep their own copies: a
// package cannot import across workspace boundaries.

export function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

export function isNonEmptyString(value: unknown): value is string {
  return typeof value === "string" && value.length > 0;
}

export function isPositiveInteger(value: unknown): value is number {
  return typeof value === "number" && Number.isInteger(value) && value > 0;
}

export function isStringList(value: unknown): value is string[] {
  return Array.isArray(value) && value.every((entry) => typeof entry === "string");
}

export function isStringRecord(value: unknown): value is Record<string, string> {
  if (!isRecord(value)) return false;
  return Object.entries(value).every(([key, entry]) => key.length > 0 && typeof entry === "string");
}

export function isOneOf(value: unknown, options: readonly string[]): boolean {
  return typeof value === "string" && options.includes(value);
}

const BASE64_PATTERN = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;

export function isBase64String(value: unknown): value is string {
  return typeof value === "string" && BASE64_PATTERN.test(value);
}

// Decoded length of a canonical base64 string without decoding it, so frame validation
// can enforce a byte cap without materializing the payload.
export function base64DecodedLength(value: string): number {
  let padding = 0;
  if (value.endsWith("==")) padding = 2;
  if (value.endsWith("=") && padding === 0) padding = 1;
  return Math.floor(value.length / 4) * 3 - padding;
}

export function isQueryParamList(value: unknown): value is [string, string][] {
  if (!Array.isArray(value)) return false;
  return value.every(
    (pair) => Array.isArray(pair) && pair.length === 2 && isNonEmptyString(pair[0]) && typeof pair[1] === "string",
  );
}

export function isIsoTimestamp(value: unknown): value is string {
  if (!isNonEmptyString(value)) return false;
  const match = value.match(
    /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.\d+)?(?:Z|([+-])(\d{2}):(\d{2}))$/,
  );
  if (!match) return false;
  const [, yearText, monthText, dayText, hourText, minuteText, secondText, , offsetHourText, offsetMinuteText] =
    match;
  const year = Number(yearText);
  const month = Number(monthText);
  const day = Number(dayText);
  const hour = Number(hourText);
  const minute = Number(minuteText);
  const second = Number(secondText);
  const offsetHour = offsetHourText === undefined ? 0 : Number(offsetHourText);
  const offsetMinute = offsetMinuteText === undefined ? 0 : Number(offsetMinuteText);
  return (
    isCalendarDate(year, month, day) &&
    isClockTime(hour, minute, second) &&
    isTimezoneOffset(offsetHour, offsetMinute) &&
    Number.isFinite(Date.parse(value))
  );
}

function isCalendarDate(year: number, month: number, day: number): boolean {
  return month >= 1 && month <= 12 && day >= 1 && day <= daysInMonth(year, month);
}

function isClockTime(hour: number, minute: number, second: number): boolean {
  return hour <= 23 && minute <= 59 && second <= 59;
}

function isTimezoneOffset(hour: number, minute: number): boolean {
  return hour <= 23 && minute <= 59;
}

function daysInMonth(year: number, month: number): number {
  if (month === 2) return isLeapYear(year) ? 29 : 28;
  return [4, 6, 9, 11].includes(month) ? 30 : 31;
}

function isLeapYear(year: number): boolean {
  return year % 4 === 0 && (year % 100 !== 0 || year % 400 === 0);
}
