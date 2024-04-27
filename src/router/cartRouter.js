
import { Router } from "express";
//import { CartManager } from "../config/CartManager.js"; //En la ruta llamo a ese CartManager 
//const cartManager = new CartManager('./src/data/cart.json')//Con esta direccion, que es donde esta alojado el carrito de mis productos 
import cartModel from "../models/cart.js";


const cartRouter = Router()

cartRouter.post('/', async (req, res) => {
    try {
        const mensaje = await cartModel.create({ products: [] })
        res.status(201).send(mensaje)
    } catch (e) {
        res.status(500).send(`Error interno del servidor al crear carrito: ${error}`)
    }
})

cartRouter.get('/:cid', async (req, res) => {
    try {
        const cartId = req.params.cid
        const cart = await cartModel.findOne({ _id: cartId }) //.populate('products.id_prod') // Populate me trae todo el contenido de id_prod
        res.status(200).send(cart)
    } catch (error) {
        res.status(500).send(`Error interno del servidor al consultar carrito: ${error}`)
    } //El Metodo "get" me devuelve todos los productos  
})

cartRouter.post('/:cid/:pid', async (req, res) => {
    try { //Actualizo la cantidad de mis productos, si no existe lo creo, si existe le aumento la cantidad
        const cartId = req.params.cid 
        const productId = req.params.pid //Envio id del producto
        const { quantity } = req.body //Envio quantity(Cantidad) del producto
        const cart = await cartModel.findById(cartId)
        //MISMA LOGICA QUE (CartManager) Consulto x el indice, si el indice no existe lo agrego y si existe lo modifico
        const indice = cart.products.findIndex(product => product.id_prod == productId)

        if (indice != -1) {
            //Consultar Stock para ver cantidades
            cart.products[indice].quantity = quantity //(caso actual deja el "quantity" como lo asignes no lo suma)  (Caso anterior asi)5 + 5 = 10, asigno 10 a quantity
        } else {
            cart.products.push({ id_prod: productId, quantity: quantity })
        }
        const mensaje = await cartModel.findByIdAndUpdate(cartId, cart)
        res.status(200).send(mensaje)
    } catch (error) {
        res.status(500).send(`Error interno del servidor al crear producto: ${error}`)
    } // Y el Metodo "Post" añiado un nuevo producto a mi array, envio un Id ( req.params.pid ) y envio en el body ( req.body )
})


export default cartRouter

//Tener en cuenta que si son varios carritos osea Complejiso este proyecto, seria la implementacion del Id como dice Coderhouse, aca resulta inecesario generar un Id si va a ser un carrito unico

