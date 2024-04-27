
import { Schema, model } from 'mongoose'

const cartSchema = new Schema({
    products: {
        type: [
            {
                id_prod: {
                    type: Schema.Types.ObjectId,
                    required: true,
                    ref: 'products'
                },
                quantity: {
                    type: Number,
                    required: true
                }
            }
        ],
        default: []
    }

})
/** 
 * Agrego el middleware() a la operacion "find" entonces solo funcionara cuando este buscando el documento,
 * asi se evita lentitud en operaciones que no lo necesitan como Updates o insertions
*/
//PRE
cartSchema.pre('findOne', function(){
    //La palabra "this" hace Ref. a "este" documento. por eso la operation populate funcionara exactamente igual a como la llamamos antes ( cartRouter.js/linea 22: .populate('products.id_prod') // Populate me trae todo el contenido de id_prod )
    this.populate('products.id_prod')
})


const cartModel = model("carts", cartSchema)


export default cartModel