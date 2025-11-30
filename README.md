# ConexaShip Backend API

Backend Express service that powers the ConexaShip customer and worker applications.

## Project Structure

```
backend/
├── package.json
├── README.md
├── .env.example
└── src/
    ├── app.js
    ├── server.js
    ├── config/
    │   └── database.js
    ├── controllers/
   │   ├── auth.controller.js
   │   ├── customers.controller.js
   │   └── workers.controller.js
    ├── middleware/
    │   ├── authenticate.js
    │   ├── authorize.js
    │   ├── error-handler.js
    │   └── rate-limiter.js
    ├── routes/
    │   ├── auth.routes.js
   │   ├── customers.routes.js
    │   ├── index.js
    │   └── workers.routes.js
    └── utils/
        └── token.js
```

## Getting Started

1. Install dependencies:
   ```bash
   npm install
   ```
2. Create an `.env` file from `.env.example` and fill the connection details for your Azure SQL instance.
3. Run the development server:
   ```bash
   npm run dev
   ```

## Environment Variables

| Name | Description |
| --- | --- |
| `PORT` | API port (default 3000) |
| `DB_SERVER` | Azure SQL host name |
| `DB_DATABASE` | Database name |
| `DB_USER` | Database user |
| `DB_PASSWORD` | Database password |
| `DB_ENCRYPT` | `true` to enable encryption (recommended for Azure SQL) |
| `DB_TRUST_CERT` | `true` when using self-signed certificates |
| `JWT_SECRET` | Secret for access tokens |
| `JWT_REFRESH_SECRET` | Secret for refresh tokens |
| `JWT_EXPIRES_IN` | Expiration (e.g., `24h`) |
| `JWT_REFRESH_EXPIRES_IN` | Refresh expiration (e.g., `30d`) |

## Next Steps

* Implement the endpoints documentados en `API_SPECIFICATION.md`.
* Usa `GET /api/customers/sample` para validar rápidamente la conexión con Azure SQL (solo para pruebas).
* Conecta las apps Flutter/Web actualizando su base URL cuando este servicio esté desplegado.
