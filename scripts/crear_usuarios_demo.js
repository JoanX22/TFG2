const mysql = require("mysql2/promise");
const bcrypt = require("bcrypt");
require("dotenv").config({
    path: "/opt/infdemic/backend/.env"
});

const usuarios = [
    {
        nombre: "Administrador INFDEMIC",
        email: "admin@infdemic.local",
        password: "Admin123!",
        rol: "administrador"
    },
    {
        nombre: "Medico Demo",
        email: "medico@infdemic.local",
        password: "Medico123!",
        rol: "medico"
    },
    {
        nombre: "Investigador Demo",
        email: "investigador@infdemic.local",
        password: "Investiga123!",
        rol: "investigador"
    }
];

async function prepararUsuarios() {
    let conexion;

    try {
        conexion = await mysql.createConnection({
            host: process.env.DB_HOST,
            user: process.env.DB_USER,
            password: process.env.DB_PASSWORD,
            database: process.env.DB_NAME
        });

        console.log("Conectado a MySQL.");

        for (const usuario of usuarios) {
            const passwordCifrada = await bcrypt.hash(
                usuario.password,
                10
            );

            const sql = `
                INSERT INTO usuarios
                    (nombre, email, password, rol)
                VALUES
                    (?, ?, ?, ?)
                ON DUPLICATE KEY UPDATE
                    nombre = VALUES(nombre),
                    password = VALUES(password),
                    rol = VALUES(rol)
            `;

            await conexion.execute(sql, [
                usuario.nombre,
                usuario.email,
                passwordCifrada,
                usuario.rol
            ]);

            console.log(
                "Usuario preparado: " +
                usuario.email +
                " - " +
                usuario.rol
            );
        }

        console.log("Usuarios preparados correctamente.");
    } catch (error) {
        console.error(
            "Error preparando usuarios:",
            error.message
        );

        process.exitCode = 1;
    } finally {
        if (conexion) {
            await conexion.end();
        }
    }
}

prepararUsuarios();
