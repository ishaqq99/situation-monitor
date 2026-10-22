/** Representative display points for country-level summaries.
 *
 * Cloudflare Radar supplies a country code, not an event coordinate. These
 * approximate capital/central points place a country summary on the globe.
 * They must never be labeled as an attack origin, victim, or IOC location.
 * A country absent from this table stays in the ranked list without a marker.
 * Add codes here only after checking their coordinates.
 * Format: ISO 3166-1 alpha-2 code -> [longitude, latitude].
 */
export const COUNTRY_POINTS: Record<string, [number, number]> = {
  AE: [54.37, 24.47], AR: [-58.38, -34.60], AT: [16.37, 48.21], AU: [149.13, -35.28],
  BD: [90.41, 23.81], BE: [4.35, 50.85], BG: [23.32, 42.70], BR: [-47.88, -15.79],
  CA: [-75.70, 45.42], CH: [7.45, 46.95], CL: [-70.67, -33.45], CN: [116.41, 39.90],
  CO: [-74.07, 4.71], CZ: [14.42, 50.08], DE: [13.40, 52.52], DK: [12.57, 55.68],
  DZ: [3.06, 36.75], EG: [31.24, 30.04], ES: [-3.70, 40.42], ET: [38.76, 9.03],
  FI: [24.94, 60.17], FR: [2.35, 48.86], GB: [-0.13, 51.51], GH: [-0.19, 5.56],
  GR: [23.73, 37.98], HK: [114.17, 22.31], HU: [19.04, 47.50], ID: [106.85, -6.21],
  IE: [-6.26, 53.35], IL: [35.21, 31.77], IN: [77.21, 28.61], IQ: [44.37, 33.31],
  IR: [51.42, 35.69], IT: [12.50, 41.90], JP: [139.69, 35.69], KE: [36.82, -1.29],
  KR: [126.98, 37.57], KZ: [71.43, 51.17], LK: [79.86, 6.93], MA: [-6.84, 34.02],
  MX: [-99.13, 19.43], MY: [101.69, 3.14], NG: [7.49, 9.07], NL: [4.90, 52.37],
  NO: [10.75, 59.91], NP: [85.32, 27.71], NZ: [174.78, -41.29], PE: [-77.04, -12.05],
  PH: [120.98, 14.60], PK: [73.05, 33.69], PL: [21.01, 52.23], PT: [-9.14, 38.72],
  RO: [26.10, 44.43], RU: [37.62, 55.75], SA: [46.68, 24.71], SE: [18.06, 59.33],
  SG: [103.82, 1.35], TH: [100.50, 13.76], TR: [32.86, 39.93], TW: [121.57, 25.03],
  UA: [30.52, 50.45], US: [-77.04, 38.90], VE: [-66.90, 10.48], VN: [105.85, 21.03],
  ZA: [28.19, -25.75],
}
