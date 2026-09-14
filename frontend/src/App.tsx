import { useEffect, useState } from "react"

interface HealthStatus {
  status: string
  api: boolean
  database: string
  redis: string
}

function App() {
  const [health, setHealth] = useState<HealthStatus | null>(null)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    async function checkBackend() {
      try {
        const response = await fetch(
          "http://127.0.0.1:8000/api/health"
        )

        if (!response.ok) {
          throw new Error("Backend returned an error")
        }

        const data: HealthStatus = await response.json()
        setHealth(data)
      } catch {
        setError("Unable to reach backend")
      }
    }

    checkBackend()
  }, [])

  return (
    <main>
      <h1>Situation Monitor</h1>

      <p>Real-time security and global situational awareness.</p>

      <h2>Platform Status</h2>

      {error && <p>{error}</p>}

      {health && (
        <div>
          <p>API status: {health.status}</p>
          <p>PostgreSQL: {health.database}</p>
          <p>Redis: {health.redis}</p>
        </div>
      )}
    </main>
  )
}

export default App