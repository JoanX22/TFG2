const express = require("express");
const mysql = require("mysql2/promise");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit").rateLimit;
require("dotenv").config();

const app = express();

const JWT_ISSUER = "infdemic";
const JWT_AUDIENCE = "infdemic-web";

const variablesNecesarias = [
    "DB_HOST",
    "DB_USER",
    "DB_PASSWORD",
    "DB_NAME",
    "JWT_SECRET"
];

for (const variable of variablesNecesarias) {
    if (!process.env[variable]) {
        console.error("Falta la variable obligatoria: " + variable);
        process.exit(1);
    }
}

app.disable("x-powered-by");
app.set("trust proxy", 1);
app.use(helmet());
app.use(express.json({ limit: "20kb" }));

const db = mysql.createPool({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
    waitForConnections: true,
    connectionLimit: 5,
    queueLimit: 0
});

const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    limit: 5,
    standardHeaders: "draft-7",
    legacyHeaders: false,
    skipSuccessfulRequests: true,
    message: {
        error:
            "Demasiados intentos de inicio de sesión. " +
            "Espera 15 minutos."
    }
});

function normalizarTexto(valor) {
    if (typeof valor !== "string") {
        return "";
    }

    return valor.trim();
}

function emailValido(email) {
    const expresion = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return expresion.test(email);
}

function esipValida(esip) {
    const expresion = /^ESIP-CV-[0-9]{6}$/;
    return expresion.test(esip);
}

function autenticarToken(req, res, next) {
    const cabecera = req.headers.authorization || "";
    const partes = cabecera.split(" ");

    if (
        partes.length !== 2 ||
        partes[0] !== "Bearer" ||
        !partes[1]
    ) {
        res.status(401).json({
            error: "Debes iniciar sesión para acceder."
        });
        return;
    }

    const token = partes[1];

    try {
        const payload = jwt.verify(
            token,
            process.env.JWT_SECRET,
            {
                algorithms: ["HS256"],
                issuer: JWT_ISSUER,
                audience: JWT_AUDIENCE
            }
        );

        req.usuario = {
            id_usuario: Number(payload.sub),
            nombre: payload.nombre,
            email: payload.email,
            rol: payload.rol
        };

        next();
    } catch (error) {
        if (error.name === "TokenExpiredError") {
            res.status(401).json({
                error:
                    "La sesión ha caducado. " +
                    "Inicia sesión otra vez."
            });
            return;
        }

        res.status(401).json({
            error: "El token no es válido."
        });
    }
}

function permitirRoles() {
    const rolesPermitidos = Array.from(arguments);

    return function (req, res, next) {
        if (
            !req.usuario ||
            !rolesPermitidos.includes(req.usuario.rol)
        ) {
            res.status(403).json({
                error:
                    "Tu usuario no tiene permiso " +
                    "para realizar esta acción."
            });
            return;
        }

        next();
    };
}

app.get("/api/health", function (req, res) {
    res.json({
        status: "ok",
        message: "Servidor INFDEMIC funcionando"
    });
});

app.post(
    "/api/login",
    loginLimiter,
    async function (req, res, next) {
        try {
            const email = normalizarTexto(
                req.body.email
            ).toLowerCase();

            const password = normalizarTexto(
                req.body.password
            );

            if (
                !emailValido(email) ||
                password.length < 6 ||
                password.length > 100
            ) {
                res.status(400).json({
                    error: "Email o contraseña no válidos."
                });
                return;
            }

            const sqlUsuario =
                "SELECT id_usuario, nombre, email, password, rol " +
                "FROM usuarios " +
                "WHERE email = ? " +
                "LIMIT 1";

            const resultadoUsuarios = await db.execute(
                sqlUsuario,
                [email]
            );

            const usuarios = resultadoUsuarios[0];

            if (usuarios.length === 0) {
                res.status(401).json({
                    error: "Credenciales incorrectas."
                });
                return;
            }

            const usuario = usuarios[0];

            const passwordCorrecta = await bcrypt.compare(
                password,
                usuario.password
            );

            if (!passwordCorrecta) {
                res.status(401).json({
                    error: "Credenciales incorrectas."
                });
                return;
            }

            const token = jwt.sign(
                {
                    nombre: usuario.nombre,
                    email: usuario.email,
                    rol: usuario.rol
                },
                process.env.JWT_SECRET,
                {
                    algorithm: "HS256",
                    expiresIn:
                        process.env.JWT_EXPIRES_IN || "1h",
                    issuer: JWT_ISSUER,
                    audience: JWT_AUDIENCE,
                    subject: String(usuario.id_usuario)
                }
            );

            res.json({
                mensaje: "Inicio de sesión correcto",
                token: token,
                usuario: {
                    id_usuario: usuario.id_usuario,
                    nombre: usuario.nombre,
                    email: usuario.email,
                    rol: usuario.rol
                }
            });
        } catch (error) {
            next(error);
        }
    }
);

app.get(
    "/api/me",
    autenticarToken,
    function (req, res) {
        res.json({
            usuario: req.usuario
        });
    }
);

app.get(
    "/api/casos",
    autenticarToken,
    permitirRoles("medico"),
    async function (req, res, next) {
        try {
            const sqlCasos =
                "SELECT id_caso, esip, hospital, diagnostico, " +
                "bacteria, riesgo, " +
                "DATE_FORMAT(fecha, '%Y-%m-%d') AS fecha " +
                "FROM casos_clinicos " +
                "ORDER BY fecha DESC";

            const resultadoCasos = await db.query(sqlCasos);
            const casos = resultadoCasos[0];

            res.json(casos);
        } catch (error) {
            next(error);
        }
    }
);

app.get(
    "/api/casos/:esip",
    autenticarToken,
    permitirRoles("medico"),
    async function (req, res, next) {
        try {
            const esip = normalizarTexto(
                req.params.esip
            ).toUpperCase();

            if (!esipValida(esip)) {
                res.status(400).json({
                    error:
                        "El formato de la ESIP no es válido."
                });
                return;
            }

            const sqlCaso =
                "SELECT id_caso, esip, hospital, diagnostico, " +
                "bacteria, riesgo, " +
                "DATE_FORMAT(fecha, '%Y-%m-%d') AS fecha " +
                "FROM casos_clinicos " +
                "WHERE esip = ?";

            const resultadoCasos = await db.execute(
                sqlCaso,
                [esip]
            );

            const casos = resultadoCasos[0];

            if (casos.length === 0) {
                res.status(404).json({
                    error: "No se encontró ningún caso."
                });
                return;
            }

            res.json(casos[0]);
        } catch (error) {
            next(error);
        }
    }
);

app.get(
    "/api/bacterias",
    autenticarToken,
    permitirRoles("medico", "investigador"),
    async function (req, res, next) {
        try {
            const sqlBacterias =
                "SELECT id_bacteria, nombre, familia, descripcion " +
                "FROM bacterias " +
                "ORDER BY nombre";

            const resultadoBacterias = await db.query(
                sqlBacterias
            );

            const bacterias = resultadoBacterias[0];

            res.json(bacterias);
        } catch (error) {
            next(error);
        }
    }
);

app.post(
    "/api/bacterias",
    autenticarToken,
    permitirRoles("investigador"),
    async function (req, res, next) {
        try {
            const nombre = normalizarTexto(
                req.body.nombre
            );

            const familia = normalizarTexto(
                req.body.familia
            );

            const descripcion = normalizarTexto(
                req.body.descripcion
            );

            if (
                nombre.length < 3 ||
                nombre.length > 100 ||
                familia.length < 3 ||
                familia.length > 100 ||
                descripcion.length < 10 ||
                descripcion.length > 1000
            ) {
                res.status(400).json({
                    error:
                        "Los datos de la bacteria no son válidos."
                });
                return;
            }

            const sqlBuscarBacteria =
                "SELECT id_bacteria " +
                "FROM bacterias " +
                "WHERE nombre = ? " +
                "LIMIT 1";

            const resultadoExistentes = await db.execute(
                sqlBuscarBacteria,
                [nombre]
            );

            const existentes = resultadoExistentes[0];

            if (existentes.length > 0) {
                res.status(409).json({
                    error: "La bacteria ya está registrada."
                });
                return;
            }

            const sqlInsertarBacteria =
                "INSERT INTO bacterias " +
                "(nombre, familia, descripcion) " +
                "VALUES (?, ?, ?)";

            const resultadoInsercion = await db.execute(
                sqlInsertarBacteria,
                [nombre, familia, descripcion]
            );

            const resultado = resultadoInsercion[0];

            res.status(201).json({
                mensaje: "Bacteria añadida correctamente.",
                id_bacteria: resultado.insertId
            });
        } catch (error) {
            next(error);
        }
    }
);

app.get(
    "/api/resistencias",
    autenticarToken,
    permitirRoles("medico", "investigador"),
    async function (req, res, next) {
        try {
            const sqlResistencias =
                "SELECT id_resistencia, bacteria, antibiotico, nivel " +
                "FROM resistencias " +
                "ORDER BY bacteria, antibiotico";

            const resultadoResistencias = await db.query(
                sqlResistencias
            );

            const resistencias = resultadoResistencias[0];

            res.json(resistencias);
        } catch (error) {
            next(error);
        }
    }
);

app.post(
    "/api/resistencias",
    autenticarToken,
    permitirRoles("investigador"),
    async function (req, res, next) {
        try {
            const bacteria = normalizarTexto(
                req.body.bacteria
            );

            const antibiotico = normalizarTexto(
                req.body.antibiotico
            );

            const nivel = normalizarTexto(
                req.body.nivel
            );

            const nivelesPermitidos = [
                "Bajo",
                "Medio",
                "Alto"
            ];

            if (
                bacteria.length < 3 ||
                bacteria.length > 100 ||
                antibiotico.length < 3 ||
                antibiotico.length > 100 ||
                !nivelesPermitidos.includes(nivel)
            ) {
                res.status(400).json({
                    error:
                        "Los datos de la resistencia no son válidos."
                });
                return;
            }

            const sqlBuscarBacteria =
                "SELECT nombre " +
                "FROM bacterias " +
                "WHERE nombre = ? " +
                "LIMIT 1";

            const resultadoBacterias = await db.execute(
                sqlBuscarBacteria,
                [bacteria]
            );

            const bacterias = resultadoBacterias[0];

            if (bacterias.length === 0) {
                res.status(400).json({
                    error:
                        "La bacteria indicada no está registrada."
                });
                return;
            }

            const sqlBuscarResistencia =
                "SELECT id_resistencia " +
                "FROM resistencias " +
                "WHERE bacteria = ? " +
                "AND antibiotico = ? " +
                "LIMIT 1";

            const resultadoExistentes = await db.execute(
                sqlBuscarResistencia,
                [bacteria, antibiotico]
            );

            const existentes = resultadoExistentes[0];

            if (existentes.length > 0) {
                res.status(409).json({
                    error:
                        "Esa resistencia ya está registrada."
                });
                return;
            }

            const sqlInsertarResistencia =
                "INSERT INTO resistencias " +
                "(bacteria, antibiotico, nivel) " +
                "VALUES (?, ?, ?)";

            const resultadoInsercion = await db.execute(
                sqlInsertarResistencia,
                [bacteria, antibiotico, nivel]
            );

            const resultado = resultadoInsercion[0];

            res.status(201).json({
                mensaje:
                    "Resistencia añadida correctamente.",
                id_resistencia: resultado.insertId
            });
        } catch (error) {
            next(error);
        }
    }
);

app.get(
    "/api/admin/estado",
    autenticarToken,
    permitirRoles("administrador"),
    async function (req, res, next) {
        try {
            const resultadoFecha = await db.query(
                "SELECT NOW() AS fecha_servidor"
            );

            const filas = resultadoFecha[0];

            res.json({
                api: "activa",
                base_datos: "conectada",
                fecha_servidor:
                    filas[0].fecha_servidor,
                tiempo_activo_segundos:
                    Math.floor(process.uptime())
            });
        } catch (error) {
            next(error);
        }
    }
);

app.use(function (req, res) {
    res.status(404).json({
        error: "Ruta no encontrada."
    });
});

app.use(function (error, req, res, next) {
    console.error("Error interno:", error.message);

    res.status(500).json({
        error: "Error interno del servidor."
    });
});

const PORT = Number(process.env.PORT) || 3000;

async function iniciarServidor() {
    try {
        await db.query("SELECT 1");

        app.listen(
            PORT,
            "127.0.0.1",
            function () {
                console.log(
                    "Backend INFDEMIC escuchando en el puerto " +
                    PORT
                );
            }
        );
    } catch (error) {
        console.error(
            "No se pudo conectar con MySQL:",
            error.message
        );

        process.exit(1);
    }
}

iniciarServidor();
