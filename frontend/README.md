# Situation Monitor frontend

React + TypeScript + Vite. See the root README for complete setup and architecture.

- `npm ci`: install the locked dependencies.
- `npm run dev`: start local development.
- `npm run build`: type-check and produce `dist/`.
- `npm run lint`: run Oxlint.
- `npm run preview`: serve the built frontend locally on port 4173.

Optional `VITE_API_BASE_URL` in `.env` configures the backend; see `.env.example`.
The value is public and read at build time. Never place credentials here.
