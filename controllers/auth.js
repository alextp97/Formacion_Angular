const { response } = require('express');
const Ususario = require('../models/Usuario');
const bcrypt = require('bcryptjs');
const { generarJWT } = require('../helpers/jwt');
const { db } = require('../models/Usuario');



//Crear usuario
const crearUsuario = async(req, res = response) => {


    const { email, name, password } = req.body;
    try {
        //Verificar el email
        const usuario = await Ususario.findOne({ email });

        if(usuario){
            return res.status(400).json({
                ok: false,
                msg: 'Ya existe un usuario con ese email'
            });
        }

    //Crear usuario
    const dbUser = new Ususario( req.body );

    //Hash la contraseña
    const salt = bcrypt.genSaltSync();
    dbUser.password = bcrypt.hashSync( password, salt );

    // Generar el JWT
    const token = await generarJWT( dbUser.id, name);

    // Crear usuario de DB
    await dbUser.save();    

    //Generar respuesta exitosa
    return res.status(201).json({
        ok: true,
        uid: dbUser.id,
        name,
        email,
        token
    })
        
    } catch (error) {

        return res.status(500).json({
            ok: false,
            msg: 'Algo salió mal, hable con el admin'
        });     
    }
}


//Login de usuario
const loginUsuario = async(req, res) => {

    const { email, password } = req.body;

    try {
        const dbUser = await Ususario.findOne({ email });

        if( !dbUser ){
            return res.status(400).json({
                ok: false,
                msg: 'El correo no existe'
            });
        }

        //Confirmar si el password hace match
        const validPassword = bcrypt.compareSync( password, dbUser.password );

        if(!validPassword){
            return res.status(400).json({
                ok: false,
                msg: 'La contraseña no es válida'
            });
        }
  
        //Generar el JWT
        const token = await generarJWT( dbUser.id, dbUser.name);

        //Respuesta del servicio
        return res.json({
            ok: true,
            uid: dbUser.id,
            name: dbUser.name,
            email: dbUser.email,
            token
        })

    } catch (error) {
        console.log(error);
        return res.status(500).json({
            ok: false,
            msg: 'Hable con el administrador'
        })
        
    }
}


//Revalidar token
const revalidarToken = async(req, res = response) => {

    const { uid } = req;

    //Leer db para obtener el email
    const dbUser = await Ususario.findById(uid);

    //Generar el JWT
    const token = await generarJWT( uid, dbUser.name );

    return res.json({
        ok: true,
        uid,
        name: dbUser.name,
        email: dbUser.email,
        token
    });
}


module.exports = {
    crearUsuario,
    loginUsuario,
    revalidarToken
}