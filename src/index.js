
//Importaciones
import express from 'express'
import mongoose from 'mongoose'
import session from 'express-session'
import MongoStore from 'connect-mongo'
import passport from 'passport'
import cookieParser from 'cookie-parser'
import messageModel from './models/messages.js'
import indexRouter from './router/indexRouter.js'
import initializePassport from './config/passport/passport.js'
import { Server } from 'socket.io'
import { engine } from 'express-handlebars'
import { __dirname } from './path.js'


//Definisiones de Importaciones // Configuraciones o declaraciones
const app = express()
const PORT = 4000

//Server
const server = app.listen(PORT, () => {
    console.log(`Server on port ${PORT}`)
})
const io = new Server(server)//Va a estar declarado un nuevo servidor de socket io

//Connection DB
mongoose.connect("mongodb+srv://martinmaidana28:coderhouse@cluster0.cuczn8s.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0")
    .then(() => console.log("DB is connected"))
    .catch(e => console.log(e))

//Permite poder ejecutar JSON // Middlewares
app.use(express.json())

app.use(session({
    secret: "secretKey",
    resave: true, //Voy a guardar cada vez que yo recargo
    store: MongoStore.create({
        mongoUrl: "mongodb+srv://martinmaidana28:coderhouse@cluster0.cuczn8s.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0",
        ttl: 60 * 60
    }),
    saveUninitialized: true //Fuerzo a que la sesion se guarde en lo que seria el storage
}))
app.use(cookieParser("secretKey"))//Firma de cookie "secretKey"
app.engine('handlebars', engine())
app.set('view engine', 'handlebars')
app.set('views', __dirname + '/views')

//Passport = SESIONES Y AUTENTICACION todo eso Delege la responsabilidad a lo que seria este Archivo de Configuracion (Passport)
initializePassport()
app.use(passport.initialize()) //Inicia todas las estrategias de autenticacion 
app.use(passport.session()) //Generame lo que serian las Session

//Routes
app.use('/', indexRouter)

//Routes Cookies, trabajando con las Cookie que le estan enviando desde lo que es el navegador 
app.get('/setCookie', (req, res) => { //Forma de Crer Cookie
    res.cookie('CookieCookie', 'Esto es una cookie :)', { maxAge: 3000000, signed: true }).send("Cookie creada") //Firma de cookie (signed: true)
})

app.get('/getCookie', (req, res) => { //Una forma de Consular la Cookie
    res.send(req.signedCookies)//Cambio de consultar todas las Cookie res.send(req.cookies) a consultar solo por las Cookies Firmadas
})

app.get('/deleteCookie', (req, res) => { //Forma de Eliminar Cookie
    res.clearCookie('CookieCookie').send("Cookie eliminada")
    //res.cookie('CookieCokie', '', { expires: new Date(0) })
})

//Session Routes

app.get('/session', (req, res) => { //Guardar sesiones de mis usuarios
    console.log(req.session)
    if (req.session.counter) { //contar las veces que mi usuario ingreso a esta ruta
        req.session.counter++
        res.send(`Sos el usuario N° ${req.session.counter} en ingresar a la pagina`) //Si ya habia ingresado
    } else { //Si ingreso por primera vez 
        req.session.counter = 1
        res.send("Sos el primer usuario que ingresa a la pagina")
    }

})

app.post('/login', (req, res) => {
    const { email, password } = req.body

    if (email == "admin@admin.com" && password == "1234") {
        req.session.email = email
        req.session.password = password

    }
    console.log(req.session)
    res.send("Login")
})

/*
//Establecer comunicacion para que pueda ingresarme informacion y yo pueda enviar informacion hacia lo que seria mi Cliente
io.on('connection', (socket) => {//Apreton de manos
    console.log("Conexion con Socket.io")

    socket.on('movimiento', info => { //Cuando el cliente me envia un mensaje, lo capturo y lo muestro
        console.log(info)
    })
    socket.on('rendirse', info => { //Cuando el cliente me envia un mensaje, lo capturo y lo muestro
        console.log(info)
        socket.emit('mensaje-jugador', "Te has rendido") //Cliente que envio este mensaje
        socket.broadcast.emit('rendicion', "El jugador se rindio") //Los Clientes que tengan establecida la comunicacion con el servidor
    })
})
*/
io.on('connection', (socket) => {
    console.log("Conexion con Socket.io")
//Msj
    socket.on('mensaje', async (mensaje) => {
        try {
            await messageModel.create(mensaje)
            const mensajes = await messageModel.find()
            io.emit('mensajeLogs', mensajes)
        } catch (e) {
            io.emit('mensajeLogs', e)
        }
    })

})


/*
app.get('/static', (req, res) => {

    const prods = [
        { id: 1, title: "Celular", price: 1500, img: "./img/170899824248166585_7797470128152.jpg" },
        { id: 2, title: "Televisor", price: 1800, img: "https://www.radiosapienza.com.ar/Image/0/500_500-526469_1.jpg" },
        { id: 3, title: "Tablet", price: 1200, img: "https://www.radiosapienza.com.ar/Image/0/500_500-526469_1.jpg" },
        { id: 4, title: "Notebook", price: 1900, img: "https://www.radiosapienza.com.ar/Image/0/500_500-526469_1.jpg" }
    ]

})
*/