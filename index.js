
const express = require('express');
const cors = require('cors');
const path = require('path')
const { dbConnection } = require('./db/config');
require('dotenv').config();


//Crear el servidor/aplicación de express
const app = express();


//Conexion a la db
dbConnection();


//Direcctorio Público
app.use( express. static('public'));


//CORS
app.use( cors() );


//Lectura y parseo del body
app.use( express.json() );


//Rutas
app.use( '/api/auth', require('./routes/auth') );


//Manejar las demás rutas
app.get( '*', (req, res) => {
    res.sendFile( path.resolve( __dirname, 'public/index.html') )
} )


app.listen( process.env.PORT, () => {
    console.log(`Servidor corriendo en el puerto ${ process.env.PORT }`)
});