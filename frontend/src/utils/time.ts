/**
 * Convert UTC/ISO timestamp string to Beijing time (UTC+8) display string.
 * Input: "2026-07-07T17:08:33Z" or "2026-07-07T17:08:33" or "2026-07-07 17:08:33"
 * Output: "2026-07-07 17:08:33" (in Beijing time)
 */
export function toBeijingTime(ts: string | null | undefined): string {
  if (!ts) return '-'
  try {
    // Handle various formats
    let date: Date
    const s = String(ts).trim()
    if (s.includes('T')) {
      date = new Date(s.endsWith('Z') ? s : s + 'Z')
    } else if (s.includes(' ')) {
      date = new Date(s.replace(' ', 'T') + '+08:00')
    } else {
      date = new Date(s)
    }
    if (isNaN(date.getTime())) return String(ts).substring(0, 19) || '-'
    // Format as Beijing time
    const bj = new Date(date.getTime() + 8 * 3600000) // UTC+8
    const y = bj.getUTCFullYear()
    const mo = String(bj.getUTCMonth() + 1).padStart(2, '0')
    const d = String(bj.getUTCDate()).padStart(2, '0')
    const h = String(bj.getUTCHours()).padStart(2, '0')
    const mi = String(bj.getUTCMinutes()).padStart(2, '0')
    const sec = String(bj.getUTCSeconds()).padStart(2, '0')
    return `${y}-${mo}-${d} ${h}:${mi}:${sec}`
  } catch {
    return String(ts).substring(0, 19) || '-'
  }
}

/**
 * Short datetime format for tables
 */
export function toBeijingShort(ts: string | null | undefined): string {
  const bj = toBeijingTime(ts)
  return bj.length >= 16 ? bj.substring(5, 16) : bj // "07-07 17:08"
}
