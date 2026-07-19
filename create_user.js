// Script para crear usuario en la base de datos
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

async function createUser() {
    try {
        console.log('Conectando a la base de datos...');
        await sql.connect(dbConfig);
        console.log('Conexión exitosa');

        // Hash de la contraseña
        const hashedPassword = await bcrypt.hash('azlanzapata143@', 10);
        
        // Insertar usuario
        const query = `
            INSERT INTO Users (username, email, password_hash, full_name, roles, allowed_apps, is_active)
            VALUES (
                @username,
                @email,
                @password,
                @fullName,
                @roles,
                @allowedApps,
                @isActive
            )
        `;
        
        const request = new sql.Request();
        request.input('username', sql.NVarChar, 'azlanzapata');
        request.input('email', sql.NVarChar, 'azlanzapata123@gmail.com');
        request.input('password', sql.NVarChar, hashedPassword);
        request.input('fullName', sql.NVarChar, 'Azlanz Zapata');
        request.input('roles', sql.NVarChar, JSON.stringify(['admin', 'operator']));
        request.input('allowedApps', sql.NVarChar, JSON.stringify(['conexaship']));
        request.input('isActive', sql.Bit, 1);
        
        await request.query(query);
        
        console.log('✅ Usuario creado exitosamente:');
        console.log('   Email: azlanzapata123@gmail.com');
        console.log('   Contraseña: azlanzapata143@');
        console.log('   Nombre: Azlanz Zapata');
        console.log('   Roles: admin, operator');
        console.log('   Apps: conexaship');
        
    } catch (err) {
        console.error('❌ Error:', err.message);
        if (err.message.includes('duplicate') || err.message.includes('unique')) {
            console.log('El usuario ya existe en la base de datos');
        }
    } finally {
        await sql.close();
    }
}

createUser();
