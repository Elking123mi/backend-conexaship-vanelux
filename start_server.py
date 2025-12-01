import os
import uvicorn

if __name__ == "__main__":
    # Railway pasa PORT como variable de entorno
    port = int(os.environ.get("PORT", 8000))
    print(f"🚀 Starting server on port {port}")
    
    uvicorn.run(
        "api_server_supabase:app",
        host="0.0.0.0",
        port=port,
        log_level="info"
    )
