
import { Schema, model } from 'mongoose'

const productSchema = new Schema({ //es solo una configuración para una ruta en un esquema
    title: { // Algunos SchemaTypes válidos en Mongoose. Plugins de mongoose
        type: String,
        required: true,
        index: true
    },
    description: {
        type: String,
        required: true
    },
    stock: {
        type: Number,
        required: true
    },
    code: {
        type: String,
        required: true,
        unique: true
    },
    price: {
        type: Number,
        required: true
    },
    thumbnail: {
        default: []
    }
})

const productModel = model("products", productSchema)

export default productModel