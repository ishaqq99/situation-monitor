// Load and display the locally stored EPSS score for one selected CVE.

import { useEffect, useState } from "react"

import { getEpssScore } from "../api/epss"
import type { EPSSScore as EPSSScoreData } from "../types/epss"


interface EpssScoreProps {
  cveId: string
  revision: string | null
}


const messageOf = (error: unknown) =>
  error instanceof Error ? error.message : "Unable to load EPSS data"


function EpssScore({ cveId, revision }: EpssScoreProps) {
  const [score, setScore] = useState<EPSSScoreData | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [isStale, setIsStale] = useState(false)

  useEffect(() => {
    const controller = new AbortController()

    async function loadScore() {
      setLoading(true)
      setScore(null)
      setError(null)
      try {
        const result = await getEpssScore(cveId, controller.signal)
        if (!controller.signal.aborted) {
          setScore(result)
          setIsStale(result !== null && (
            Date.now() - Date.parse(`${result.score_date}T00:00:00Z`)
          ) > 172_800_000)
        }
      } catch (requestError) {
        if (!controller.signal.aborted) setError(messageOf(requestError))
      } finally {
        if (!controller.signal.aborted) setLoading(false)
      }
    }

    void loadScore()
    return () => controller.abort()
  }, [cveId, revision])

  return (
    <div className="kev-detail-section">
      <strong>EPSS exploitation probability</strong>
      <p>FIRST's estimate of exploitation in the next 30 days.
        Percentile is relative ranking, not another probability.</p>

      {loading && <p role="status">Loading stored EPSS score...</p>}
      {error && <p className="error-message" role="alert">{error}</p>}

      {!loading && !error && score === null && (
        <p>No EPSS score is stored yet. The daily enrichment may still be running.</p>
      )}

      {!loading && !error && score && (
        <div className="kev-details-grid">
          <div>
            <strong>Probability</strong>
            <p>{(score.epss_score * 100).toFixed(2)}%</p>
          </div>
          <div>
            <strong>Percentile</strong>
            <p>{(score.percentile * 100).toFixed(2)}%</p>
          </div>
          <div>
            <strong>Score date</strong>
            <p>{score.score_date}</p>
          </div>
          {isStale && (
            <p className="status-warning">This stored score is over two days old.</p>
          )}
        </div>
      )}
    </div>
  )
}


export default EpssScore
