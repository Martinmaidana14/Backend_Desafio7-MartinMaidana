
import local from 'passport-local'
import passport from 'passport'
import { userModel } from '../../models/user.js'
import { createHash, validatePassword } from '../../utils/bcrypt.js'

//Passport: Me permite a mi tener de una forma muy sencilla en un solo archivo de configuracion todas las estrategias de autenticacion que yo necesite(Datos Biometricos, Redes Sociales, Etc...)
//Paso1: Definir nombre de estrategia = ('register'), paso2: 
//Passport trabaje con uno o mas middlewares (localStrategy) se implementa para lo que seria User y password normal(es la mas simple), paso3: luego viene la misma logica que hice para registros de usuarios LINE 17-27
const localStrategy = local.Strategy

const initializePassport = () => {
    //Definir en que rutas se aplican mis estrategias

    passport.use('register', new localStrategy({ passReqToCallback: true, usernameField: 'email' }, async (req, username, password, done) => {
        try {
            const { first_name, last_name, email, password, age } = req.body
            const findUser = await userModel.findOne({ email: email })
            if (findUser) {
                return done(null, false)
            } else {
                const user = await userModel.create({ first_name: first_name, last_name: last_name, email: email, age: age, password: createHash(password) })
                return done(null, user)
            }
        } catch (e) {
            return done(e)
        }
    }))


        //1.Genera, Inicializar la sesion del usuario
        passport.serializeUser((user, done) => {
            done(null, user._id)
        })
    
        //2.Elimina, Eliminar la sesion del usuario
        passport.deserializeUser(async (id, done) => {
            const user = await userModel.findById(id)
            done(null, user)
        })

        passport.use('login', new localStrategy({ usernameField: 'email' }, async (username, password, done) => {
            try {
                const user = await userModel.findOne({ email: username }).lean()
                if (user && validatePassword(password, user.password)) {
                    return done(null, user)
                } else {
                    return done(null, false)
                }
            } catch (e) {
                return done(e)
            }
        }))
    }


    export default initializePassport