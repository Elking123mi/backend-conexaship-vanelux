-- Script SQL para agregar columnas faltantes en driver_applications
-- Ejecutar en Supabase SQL Editor: https://supabase.com/dashboard/project/ujkddikmljvccpwrgnvz/sql

-- Agregar columnas para sistema de aprobación con JWT
ALTER TABLE driver_applications 
ADD COLUMN IF NOT EXISTS setup_token TEXT;

ALTER TABLE driver_applications 
ADD COLUMN IF NOT EXISTS approved_at TIMESTAMPTZ;

ALTER TABLE driver_applications 
ADD COLUMN IF NOT EXISTS admin_note TEXT;

ALTER TABLE driver_applications 
ADD COLUMN IF NOT EXISTS user_id INT REFERENCES users(id);

-- Índice para búsquedas por user_id
CREATE INDEX IF NOT EXISTS idx_driver_applications_user_id ON driver_applications(user_id);

-- Comentarios
COMMENT ON COLUMN driver_applications.setup_token IS 'JWT token para crear contraseña (válido 72h)';
COMMENT ON COLUMN driver_applications.approved_at IS 'Fecha de aprobación';
COMMENT ON COLUMN driver_applications.admin_note IS 'Nota del admin al aprobar/rechazar';
COMMENT ON COLUMN driver_applications.user_id IS 'FK a users, se asigna al crear cuenta (status=onboarded)';
