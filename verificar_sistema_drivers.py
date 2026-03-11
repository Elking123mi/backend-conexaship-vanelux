"""
Script para verificar que el sistema de drivers está funcionando correctamente.
Ejecutar: python verificar_sistema_drivers.py
"""
import requests
import json
from datetime import datetime, timedelta

# Configuración
BACKEND_URL = "https://web-production-700fe.up.railway.app"
# BACKEND_URL = "http://localhost:3000"  # Para testing local

def test_submit_application():
    """Test 1: Enviar aplicación de conductor"""
    print("\n" + "="*70)
    print("TEST 1: Enviar aplicación de conductor (público)")
    print("="*70)
    
    application_data = {
        "full_name": "Juan Test Driver",
        "email": "juan.testdriver@example.com",
        "phone": "+1 305-555-0123",
        "driver_license": "D123TEST",
        "license_expiry_date": "2026-12-31",
        "vehicle_type": "Sedan",
        "vehicle_make": "Mercedes-Benz",
        "vehicle_model": "S-Class",
        "vehicle_year": 2024,
        "vehicle_color": "Black",
        "license_plate": "TEST-123",
        "insurance_company": "Test Insurance Co",
        "insurance_policy_number": "POL-123456789",
        "insurance_expiry_date": "2026-12-31",
        "years_of_experience": 5,
        "languages": "Español, Inglés",
        "has_background_check": True,
        "additional_notes": "Test application from verification script"
    }
    
    try:
        response = requests.post(
            f"{BACKEND_URL}/api/v1/vlx/drivers/apply",
            json=application_data,
            headers={"Content-Type": "application/json"},
            timeout=10
        )
        
        print(f"\nStatus Code: {response.status_code}")
        print(f"Response: {json.dumps(response.json(), indent=2)}")
        
        if response.status_code == 201:
            print("\n✅ ÉXITO: Aplicación enviada correctamente")
            print(f"   Application ID: {response.json().get('application_id')}")
            print(f"   Email enviado al admin: {response.json().get('email_sent')}")
            return response.json().get('application_id')
        else:
            print(f"\n❌ ERROR: {response.json().get('detail', 'Unknown error')}")
            return None
            
    except requests.exceptions.ConnectionError:
        print("\n❌ ERROR DE CONEXIÓN: No se pudo conectar al backend")
        print(f"   URL: {BACKEND_URL}")
        print("   ¿El backend está corriendo?")
        return None
    except Exception as e:
        print(f"\n❌ ERROR: {str(e)}")
        return None


def test_list_applications(admin_token=None):
    """Test 2: Listar aplicaciones (requiere token admin)"""
    print("\n" + "="*70)
    print("TEST 2: Listar aplicaciones (requiere auth admin)")
    print("="*70)
    
    if not admin_token:
        print("\n⚠️ OMITIDO: No se proporcionó token de admin")
        print("   Para probar este endpoint, primero haz login con un usuario admin")
        print("   y pasa el access_token a esta función")
        return
    
    try:
        response = requests.get(
            f"{BACKEND_URL}/api/v1/vlx/drivers/applications?status_filter=pending",
            headers={
                "Authorization": f"Bearer {admin_token}",
                "Content-Type": "application/json"
            },
            timeout=10
        )
        
        print(f"\nStatus Code: {response.status_code}")
        
        if response.status_code == 200:
            data = response.json()
            print(f"\n✅ ÉXITO: {data.get('total', 0)} aplicaciones encontradas")
            
            if data.get('applications'):
                print("\nPrimeras 3 aplicaciones:")
                for i, app in enumerate(data['applications'][:3], 1):
                    print(f"\n{i}. {app.get('full_name')} ({app.get('email')})")
                    print(f"   ID: {app.get('id')}")
                    print(f"   Status: {app.get('status')}")
                    print(f"   Created: {app.get('created_at')}")
        else:
            print(f"\n❌ ERROR: {response.json().get('detail', 'Unknown error')}")
            
    except Exception as e:
        print(f"\n❌ ERROR: {str(e)}")


def test_backend_health():
    """Test 0: Verificar que el backend está online"""
    print("\n" + "="*70)
    print("TEST 0: Verificar estado del backend")
    print("="*70)
    
    try:
        response = requests.get(f"{BACKEND_URL}/", timeout=5)
        print(f"\nStatus Code: {response.status_code}")
        print(f"Response: {json.dumps(response.json(), indent=2)}")
        
        if response.status_code == 200:
            print("\n✅ Backend está online y responde correctamente")
            return True
        else:
            print("\n⚠️ Backend responde pero con código inesperado")
            return False
            
    except requests.exceptions.ConnectionError:
        print(f"\n❌ ERROR: No se puede conectar a {BACKEND_URL}")
        print("   Verifica que el backend esté corriendo")
        return False
    except Exception as e:
        print(f"\n❌ ERROR: {str(e)}")
        return False


def print_summary():
    """Imprimir resumen de verificación"""
    print("\n" + "="*70)
    print("RESUMEN DE VERIFICACIÓN")
    print("="*70)
    
    print("\n✅ Endpoints Verificados:")
    print("   • POST /api/v1/vlx/drivers/apply (público)")
    print("\n⚠️ Endpoints Requieren Auth Admin (no probados):")
    print("   • GET /api/v1/vlx/drivers/applications")
    print("   • POST /api/v1/vlx/drivers/applications/{id}/approve")
    print("   • POST /api/v1/vlx/drivers/applications/{id}/reject")
    print("\n📧 Emails que Deberías Recibir:")
    print("   • Email al admin con datos del driver")
    print("   • Email al driver confirmando recepción")
    print("\n📋 Próximos Pasos:")
    print("   1. Verifica que llegaron los 2 emails")
    print("   2. Ve a Supabase y busca la nueva aplicación en driver_applications")
    print("   3. Login en vanelux.netlify.app con usuario admin")
    print("   4. Ve a menú usuario → 'Driver Applications'")
    print("   5. Aprueba la aplicación de prueba")
    print("   6. Verifica que el driver recibe email con link de setup")


if __name__ == "__main__":
    print("🚗 VERIFICACIÓN DEL SISTEMA DE DRIVERS VANELUX")
    print(f"Backend URL: {BACKEND_URL}")
    
    # Test 0: Backend health
    if not test_backend_health():
        print("\n❌ Backend no está disponible. Abortando tests.")
        exit(1)
    
    # Test 1: Submit application (público)
    application_id = test_submit_application()
    
    # Test 2: List applications (requiere admin token)
    # Para probarlo con tu token:
    # YOUR_ADMIN_TOKEN = "eyJhbGc..."  # Token que obtienes al hacer login
    # test_list_applications(YOUR_ADMIN_TOKEN)
    test_list_applications(None)
    
    # Resumen
    print_summary()
    
    print("\n" + "="*70)
    print("✅ VERIFICACIÓN COMPLETA")
    print("="*70 + "\n")
