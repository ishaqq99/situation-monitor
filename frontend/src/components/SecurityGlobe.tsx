/**
 * Interactive globe for the dashboard's center panel.
 *
 * WHY: MapLibre renders the real world using OpenFreeMap's dark vector style.
 * App.tsx passes a Cloudflare Radar country summary. Marker points are
 * representative country locations, never exact attack coordinates.
 */
import { useEffect, useRef, useState } from "react"
import { Map, Marker, NavigationControl, Popup, setWorkerUrl } from "maplibre-gl"
import workerUrl from "maplibre-gl/dist/maplibre-gl-worker.mjs?worker&url"
import "maplibre-gl/dist/maplibre-gl.css"
import { COUNTRY_POINTS } from "../data/countryPoints"
import type { ThreatOverview } from "../types/threat"

// Vite bundles the tile-decoding worker as its own URL. Configure it before
// Map construction so both local development and production builds work.
setWorkerUrl(workerUrl)

/** Create exactly one map per mount and dispose of it on unmount. */
export default function SecurityGlobe({ overview }: { overview: ThreatOverview | null }) {
  const container = useRef<HTMLDivElement | null>(null)
  const mapRef = useRef<Map | null>(null)
  const [ready, setReady] = useState(false)
  const [error, setError] = useState(false)

  useEffect(() => {
    if (!container.current) return

    let map: Map
    try {
      map = new Map({
        container: container.current,
        style: "https://tiles.openfreemap.org/styles/dark",
        center: [-16, 19],
        zoom: 1.45,
        minZoom: 1,
        maxZoom: 8,
      })
    } catch {
      setError(true)
      return
    }
    mapRef.current = map

    // Loading a style resets projection; switch to the globe once it loads.
    map.on("style.load", () => map.setProjection({ type: "globe" }))
    map.on("load", () => setReady(true))
    map.on("error", () => {
      if (!map.loaded()) setError(true)
    })
    map.addControl(new NavigationControl({ showCompass: true }), "bottom-right")
    map.scrollZoom.disable() // Page scroll should not unexpectedly zoom Earth.

    const observer = new ResizeObserver(() => map.resize())
    observer.observe(container.current)
    return () => {
      observer.disconnect()
      mapRef.current = null
      map.remove() // Prevent duplicate maps during React StrictMode remounts.
    }
  }, [])

  // A new data snapshot replaces the previous markers. Building popup content
  // with textContent avoids injecting provider text as HTML into the page.
  useEffect(() => {
    const map = mapRef.current
    if (!ready || !map || !overview) return
    const markers: Marker[] = []
    const popups: Popup[] = []
    for (const country of overview.countries) {
      const point = COUNTRY_POINTS[country.country_code]
      if (!point) continue
      const button = document.createElement("button")
      button.type = "button"
      button.className = "threat-marker"
      button.title = `${country.country_name}: ${country.percentage.toFixed(2)}% of mitigated requests`
      button.setAttribute("aria-label", button.title)
      const marker = new Marker({ element: button }).setLngLat(point).addTo(map)
      markers.push(marker)
      button.addEventListener("click", () => {
        popups.forEach(popup => popup.remove())
        const content = document.createElement("div")
        content.className = "threat-popup"
        const title = document.createElement("strong")
        title.textContent = country.country_name
        const detail = document.createElement("p")
        detail.textContent = `${country.percentage.toFixed(2)}% of Cloudflare-mitigated HTTP requests in this snapshot had a source IP geolocated to this country.`
        content.append(title, detail)
        popups.push(new Popup({ offset: 16 }).setLngLat(point).setDOMContent(content).addTo(map))
      })
    }
    return () => { markers.forEach(marker => marker.remove()); popups.forEach(popup => popup.remove()) }
  }, [ready, overview])

  return (
    <div className="security-globe">
      <div ref={container} className="security-globe-map" aria-label="Interactive world globe" />
      {!ready && !error && <div className="globe-message" role="status">Loading world map…</div>}
      {error && !ready && (
        <div className="globe-message" role="status">
          Map tiles are unavailable. Check the browser network connection.
        </div>
      )}
      <div className="globe-overlay" aria-hidden="true">
        <span className="globe-corner globe-corner-tl" />
        <span className="globe-corner globe-corner-tr" />
        <span className="globe-corner globe-corner-bl" />
        <span className="globe-corner globe-corner-br" />
      </div>
    </div>
  )
}
