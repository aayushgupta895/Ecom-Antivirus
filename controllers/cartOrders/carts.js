import ErrorHandler from '../../Error/errorHandler.js'
import asyncErrorHandler from '../../Error/asyncErrorHandler.js'
import { db } from '../../models/index.js';
import User from '../../models/user/users.js';
import { getUserCart } from '../../utils/utils.js';

const { Cart } = db

export const updateCart = asyncErrorHandler(async (req, res, next) => {

    const userId = req.params.userId;
    const { products } = req.body;

    const user = await getUserCart(req, res, next);

    const newProducts = []

    for (const product of products) {

        const { productId, quantity } = product;

        const existingProduct = await db.Product.findOne({ where: { productId } });
        if (!existingProduct) next(new ErrorHandler(`Product: ${productId} does not exist`, 400, "Please check products provided"));

        if (quantity < 0) next(new ErrorHandler(`Quantity of product: ${productId} cannot be negative`, 400, "Please check products provided"));

        const productIndex = user.products.findIndex(product => {
            return product.productId === productId;
        });

        if (productIndex == -1) {

            const obj = {
                productId: productId,
                quantity: quantity,
                name: existingProduct.name,
            }
            newProducts.push(obj);

        } else {

            if (quantity == 0) {

                user.products.splice(productIndex, 1);

            } else if (quantity >= 1) {

                user.products[productIndex].quantity = quantity;
                user.products[productIndex].name = existingProduct.name;

            } else {
                return next("quantity cannot be in negative", 400);
            }
        }
    }

    if (newProducts.length > 0)
        user.products.push(...newProducts);

    const [affectedRows, rows] = await Cart.update({
        products: user.products
    }, {
        where: {
            userId: userId,
        },
        returning: true
    })

    return res.status(200).json(...rows)

})

export const getCartByUser = asyncErrorHandler(async (req, res, next) => {

    const cart = await getUserCart(req, res, next)

    return res.status(200).send(cart);

})