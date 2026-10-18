/**
 * Interactive globe for the dashboard's center panel.
 *
 * WHY: MapLibre renders the real world using OpenFreeMap's dark vector style.
 * App.tsx mounts this component. It calls the public map-tile service only;
 * it does not call our backend or invent threat coordinates. Real sourced
 * event markers are a separate next step.
 */
import { useEffect, useRef, useState } from "react"
import { Map, NavigationControl, setWorkerUrl } from "maplibre-gl"
import workerUrl from "maplibre-gl/dist/maplibre-gl-worker.mjs?worker&url"
import "maplibre-gl/dist/maplibre-gl.css"

// Vite bundles the tile-decoding worker as its own URL. Configure it before
// Map construction so both local development and production builds work.
setWorkerUrl(workerUrl)

/** Create exactly one map per mount and dispose of it on unmount. */
export default function SecurityGlobe() {
  const container = useRef<HTMLDivElement | null>(null)
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
      map.remove() // Prevent duplicate maps during React StrictMode remounts.
    }
  }, [])

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
