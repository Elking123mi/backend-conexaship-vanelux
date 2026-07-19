const sql = require('mssql');
const bcrypt = require('bcrypt');
require('dotenv').config();

const dbConfig = {
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    server: process.env.DB_SERVER,
    database: process.env.DB_NAME,
    options: {
        encrypt: true,
        trustServerCertificate: false
    }
};

async function updateCEOPassword() {
    try {
        console.log('🔐 Actualizando contraseña del CEO...');
        await sql.connect(dbConfig);
        console.log('✅ Conectado a la base de datos');

        // Hash de la nueva contraseña
        const newPassword = 'chila2006123';
        const hashedPassword = await bcrypt.hash(newPassword, 10);
        
        // Actualizar contraseña del usuario CEO (ID: 14)
        const query = `
            UPDATE Users 
            SET password_hash = @password
            WHERE id = 14 AND username = 'Elkin2006'
        `;
        
        const request = new sql.Request();
        request.input('password', sql.NVarChar, hashedPassword);
        
        const result = await request.query(query);
        
        if (result.rowsAffected[0] > 0) {
            console.log('✅ Contraseña actualizada exitosamente!');
            console.log('');
            console.log('📋 CREDENCIALES DEL CEO:');
            console.log('   Username: Elkin2006');
            console.log('   Email: Elkin2006@officeexecutive.cl');
            console.log('   Password: chila2006123');
            console.log('   Roles: ceo, executive, admin');
            console.log('');
            console.log('🚀 Ya puedes hacer login en la app interna!');
        } else {
            console.log('⚠️  No se encontró el usuario CEO');
        }
        
    } catch (err) {
        console.error('❌ Error:', err.message);
    } finally {
        await sql.close();
    }
}

updateCEOPassword();
